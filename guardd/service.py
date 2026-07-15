from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from guardd.approvals import ApprovalManager
from guardd.audit import AuditStore
from guardd.config import Settings
from guardd.correlation import CorrelationEngine
from guardd.models.decisions import Decision, DecisionKind
from guardd.models.events import GuardEvent, ToolResultEvent
from guardd.policy import PolicyEngine, PolicyLoader, PolicyValidationError
from guardd.security import digest_payload, sanitize


class GuardService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.loader = PolicyLoader()
        self.policy = self.loader.load(settings.policy_path)
        self.engine = PolicyEngine(self.policy, settings.workspace)
        self.store = AuditStore(settings.db_path, settings.emergency_log_path, self.engine.secret_patterns)
        self.approvals = ApprovalManager(self.store, settings.approval_ttl_seconds)
        limits = self.policy.document.get("budgets", {})
        self.correlation = CorrelationEngine(
            tool_budget=int(limits.get("tool_calls_per_10m", 200)),
            repeat_limit=int(limits.get("same_action_per_minute", 5)),
            subagent_limit=int(limits.get("subagents", 3)),
            file_limit=int(limits.get("files_per_operation", 100)),
            byte_limit=int(limits.get("bytes_per_operation", 50_000_000)),
            delete_ratio_limit=float(limits.get("delete_ratio", 0.5)),
        )
        self._events: dict[UUID, GuardEvent] = {}
        self._policy_lock = threading.RLock()
        self._restore_recent_state()
        self.store.record_policy(self.policy.digest, self.policy.document.get("version"), str(self.policy.source), self.policy.document)

    def _restore_recent_state(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        with self.store._lock:
            rows = self.store._connection.execute(
                "SELECT e.sanitized_json, EXISTS(SELECT 1 FROM tool_results t WHERE t.event_id=e.event_id AND t.success=1) AS successful "
                "FROM events e WHERE e.occurred_at>=? ORDER BY e.occurred_at",
                (cutoff,),
            ).fetchall()
        for row in rows:
            try:
                event = GuardEvent.model_validate(json.loads(row["sanitized_json"]))
            except (ValueError, json.JSONDecodeError):
                continue
            self.correlation.restore_event(event, bool(row["successful"]) and "read" in event.derived.get("actions", []))

    def decide(self, event: GuardEvent) -> Decision:
        try:
            with self._policy_lock:
                event = self.engine.normalize(event)
                correlations = self.correlation.evaluate(event)
                decision = self.engine.decide(event, correlations)
        except Exception as exc:
            proposed = DecisionKind(str(self.policy.document.get("defaults", {}).get("on_parse_error", "require_approval")).upper())
            effective = DecisionKind.OBSERVE if self.policy.mode == "observe" else proposed
            clean, classifications = sanitize(event.params, extra_patterns=self.engine.secret_patterns)
            event.data_classification = sorted(set(event.data_classification + classifications))
            decision = Decision(
                event_id=event.event_id, decision=effective,
                would_decide=proposed if effective != proposed else None,
                risk="high", rule_ids=["NORMALIZATION-ERROR-001"],
                reason="Event normalization failed; action was not silently allowed",
                effective_mode=self.policy.mode,
                parameter_digest=digest_payload({"agent": event.agent_id, "session": event.session_key, "tool": event.tool.model_dump() if event.tool else None, "params": event.params}),
                sanitized_params=clean,
                remediation="Review the raw action locally and approve once only if its exact target is understood",
            )
            self.store.incident("high", "normalization_error", str(exc), {"event_id": str(event.event_id)})
        self._events[event.event_id] = event
        if len(self._events) > 5000:
            self._events.pop(next(iter(self._events)))
        try:
            self.store.record_event(event)
            self.store.record_decision(decision, self.policy.digest)
        except sqlite3.Error:
            if decision.risk in {"high", "critical"}:
                decision.decision = DecisionKind.DENY
                decision.reason += "; audit store unavailable, failed closed"
        if decision.decision == DecisionKind.REQUIRE_APPROVAL:
            self.approvals.create(event, decision)
        self.correlation.record_decision(event, decision.risk)
        return decision

    def resolve_approval(self, approval_id: UUID, allow: bool, operator: str) -> dict[str, Any]:
        result = self.approvals.resolve(approval_id, allow, operator)
        if not allow:
            event = self._events.get(UUID(result["event_id"]))
            if event:
                self.correlation.record_denial(event)
        return result

    def tool_result(self, result: ToolResultEvent) -> None:
        self.store.record_tool_result(result)
        event = self._events.get(result.event_id)
        if event:
            size = len(str(result.output).encode("utf-8")) if result.output is not None else 0
            self.correlation.record_result(event, result.success, size)

    def session_event(self, event: GuardEvent) -> None:
        event = self.engine.normalize(event)
        self.correlation.session_event(event)
        self.store.record_event(event)
        status = "ended" if event.event_type.endswith("end") else "active"
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "INSERT INTO sessions(session_key, agent_id, status, started_at, ended_at, metadata_json) VALUES (?, ?, ?, ?, ?, '{}') "
                "ON CONFLICT(session_key) DO UPDATE SET status=excluded.status, ended_at=excluded.ended_at",
                (event.session_key, event.agent_id, status, event.occurred_at.isoformat(), event.occurred_at.isoformat() if status == "ended" else None),
            )

    def validate_policy(self, text: str) -> dict[str, Any]:
        try:
            policy = self.loader.parse(text)
            return {"valid": True, "digest": policy.digest, "errors": []}
        except PolicyValidationError as exc:
            return {"valid": False, "errors": [str(exc)]}

    def simulate(self, event: GuardEvent) -> Decision:
        with self._policy_lock:
            normalized = self.engine.normalize(event)
            return self.engine.decide(normalized, [])

    def reload_policy(self, operator: str = "local-operator") -> dict[str, Any]:
        candidate = self.loader.load(self.settings.policy_path)
        with self._policy_lock:
            self.policy = candidate
            self.engine = PolicyEngine(candidate, self.settings.workspace)
            self.store.secret_patterns = self.engine.secret_patterns
        self.store.record_policy(candidate.digest, candidate.document.get("version"), str(candidate.source), candidate.document, operator)
        return {"digest": candidate.digest, "mode": candidate.mode}

    def status(self) -> dict[str, Any]:
        return {
            "version": "0.1.0", "mode": self.policy.mode, "policy_digest": self.policy.digest,
            "policy_source": str(self.policy.source), "workspace": str(self.settings.workspace),
            "database": str(self.settings.db_path), "database_integrity": self.store.integrity_check(),
            **self.store.status_counts(),
        }

    def close(self) -> None:
        self.store.close()
