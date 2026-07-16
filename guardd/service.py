from __future__ import annotations

import json
import sqlite3
import threading
import difflib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

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
        if settings.audit_retention_days > 0:
            retention = self.store.purge_before(
                (datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)).isoformat()
            )
            if any(retention.values()):
                self.store.record_operator_action("retention.purge", "startup", "audit", detail=retention)
        self.approvals = ApprovalManager(self.store, settings.approval_ttl_seconds)
        self.correlation = self._create_correlation(self.policy.document)
        self._event_sink: Callable[[str, dict[str, Any]], None] | None = None
        self._events: dict[UUID, GuardEvent] = {}
        self._policy_lock = threading.RLock()
        self._restore_recent_state()
        self.store.record_policy(self.policy.digest, self.policy.document.get("version"), str(self.policy.source), self.policy.document)

    @staticmethod
    def _create_correlation(document: dict[str, Any]) -> CorrelationEngine:
        limits = document.get("budgets", {})
        return CorrelationEngine(
            tool_budget=int(limits.get("tool_calls_per_10m", 200)),
            repeat_limit=int(limits.get("same_action_per_minute", 5)),
            subagent_limit=int(limits.get("subagents", 3)),
            file_limit=int(limits.get("files_per_operation", 100)),
            byte_limit=int(limits.get("bytes_per_operation", 50_000_000)),
            delete_ratio_limit=float(limits.get("delete_ratio", 0.5)),
        )

    def set_event_sink(self, sink: Callable[[str, dict[str, Any]], None] | None) -> None:
        self._event_sink = sink
        self.store.set_event_sink(sink)

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        if self._event_sink:
            try:
                self._event_sink(event_type, data)
            except Exception:
                pass

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
        self._emit("event.recorded", {"event_id": str(event.event_id), "session_key": event.session_key})
        self._emit("decision.recorded", {"event_id": str(event.event_id), "decision": decision.decision.value, "risk": decision.risk})
        if decision.approval_id:
            self._emit("approval.created", {"approval_id": str(decision.approval_id), "expires_at": decision.expires_at})
        return decision

    def resolve_approval(self, approval_id: UUID, allow: bool, operator: str) -> dict[str, Any]:
        result = self.approvals.resolve(approval_id, allow, operator)
        if not allow:
            event = self._events.get(UUID(result["event_id"]))
            if event:
                self.correlation.record_denial(event)
        self.store.record_operator_action(
            "approval.allow_once" if allow else "approval.deny", operator, "approval", str(approval_id),
            {"event_id": result["event_id"], "status": result["status"], "parameter_digest": result["parameter_digest"]},
        )
        self._emit("approval.resolved", {"approval_id": str(approval_id), "status": result["status"]})
        return result

    def tool_result(self, result: ToolResultEvent) -> None:
        self.store.record_tool_result(result)
        event = self._events.get(result.event_id)
        if event:
            size = len(str(result.output).encode("utf-8")) if result.output is not None else 0
            self.correlation.record_result(event, result.success, size)
        self._emit("event.tool_result", {"event_id": str(result.event_id), "success": result.success})

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
        self._emit("session.updated", {"session_key": event.session_key, "status": status})

    def validate_policy(self, text: str) -> dict[str, Any]:
        try:
            policy = self.loader.parse(text, self.settings.policy_path)
            return {
                "valid": True, "digest": policy.digest, "errors": [],
                "summary": self._policy_summary(policy.document),
            }
        except PolicyValidationError as exc:
            return {"valid": False, "errors": [str(exc)]}

    def simulate(self, event: GuardEvent) -> Decision:
        with self._policy_lock:
            normalized = self.engine.normalize(event)
            return self.engine.decide(normalized, [])

    def simulate_candidate(self, text: str, event: GuardEvent) -> Decision:
        candidate = self.loader.parse(text, self.settings.policy_path)
        engine = PolicyEngine(candidate, self.settings.workspace)
        normalized = engine.normalize(event.model_copy(deep=True, update={"derived": {}}))
        return engine.decide(normalized, [])

    @staticmethod
    def _policy_summary(document: dict[str, Any]) -> dict[str, Any]:
        rules = document.get("rules", [])
        counts: dict[str, int] = {}
        risks: dict[str, int] = {}
        for rule in rules:
            decision = str(rule.get("decision", "unknown")).upper()
            risk = str(rule.get("risk", "unknown"))
            counts[decision] = counts.get(decision, 0) + 1
            risks[risk] = risks.get(risk, 0) + 1
        return {
            "mode": str(document.get("defaults", {}).get("mode", "observe")),
            "default_decision": str(document.get("defaults", {}).get("decision", "require_approval")),
            "rules": len(rules), "decisions": counts, "risks": risks,
            "budgets": document.get("budgets", {}),
            "allow_domains": document.get("network", {}).get("allow_domains", []),
            "deny_domains": document.get("network", {}).get("deny_domains", []),
        }

    def get_policy(self) -> dict[str, Any]:
        text = self.settings.policy_path.read_text(encoding="utf-8")
        stat = self.settings.policy_path.stat()
        return {
            "text": text, "digest": self.policy.digest, "mode": self.policy.mode,
            "source": str(self.settings.policy_path),
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "summary": self._policy_summary(self.policy.document),
        }

    def policy_diff(self, text: str) -> dict[str, Any]:
        candidate = self.loader.parse(text, self.settings.policy_path)
        current_text = self.settings.policy_path.read_text(encoding="utf-8")
        diff = list(difflib.unified_diff(
            current_text.splitlines(), text.splitlines(), fromfile="current", tofile="candidate", lineterm="",
        ))
        current_rules = {str(item.get("id")): item for item in self.policy.document.get("rules", [])}
        candidate_rules = {str(item.get("id")): item for item in candidate.document.get("rules", [])}
        old_budgets = self.policy.document.get("budgets", {})
        new_budgets = candidate.document.get("budgets", {})
        relaxed_budgets = {
            key: {"from": old_budgets.get(key), "to": value}
            for key, value in new_budgets.items()
            if key in old_budgets and isinstance(value, (int, float)) and isinstance(old_budgets[key], (int, float)) and value > old_budgets[key]
        }
        return {
            "candidate_digest": candidate.digest,
            "diff": diff,
            "impact": {
                "mode": {"from": self.policy.mode, "to": candidate.mode},
                "rules_added": sorted(candidate_rules.keys() - current_rules.keys()),
                "rules_removed": sorted(current_rules.keys() - candidate_rules.keys()),
                "rules_changed": sorted(key for key in current_rules.keys() & candidate_rules.keys() if current_rules[key] != candidate_rules[key]),
                "relaxed_budgets": relaxed_budgets,
                "allow_domains_added": sorted(set(candidate.document.get("network", {}).get("allow_domains", [])) - set(self.policy.document.get("network", {}).get("allow_domains", []))),
            },
        }

    def regression_policy(self, text: str, session_key: str | None = None) -> dict[str, Any]:
        candidate = self.loader.parse(text, self.settings.policy_path)
        results: list[dict[str, Any]] = []
        if session_key:
            # A session replay must preserve the deployed workspace and network
            # semantics because it answers what this host would decide now.
            engine = PolicyEngine(candidate, self.settings.workspace)
            events = self.store.replay_events(session_key)
            for raw in events:
                try:
                    event = GuardEvent.model_validate(raw)
                    decision = engine.decide(engine.normalize(event.model_copy(deep=True, update={"derived": {}})), [])
                    proposed = decision.would_decide or decision.decision
                    results.append({"event_id": str(event.event_id), "decision": proposed.value, "risk": decision.risk, "rule_ids": decision.rule_ids})
                except (ValueError, KeyError) as exc:
                    results.append({"error": str(exc)})
            return {"source": "session", "session_key": session_key, "passed": all("error" not in item for item in results), "results": results}

        fixtures_root = Path(__file__).parents[1] / "fixtures"
        # Built-in fixtures are a deterministic policy regression suite, not a
        # replay of the current host. Run them in an isolated workspace and do
        # not let live DNS or the GuardAgent source path change their outcome.
        with tempfile.TemporaryDirectory(prefix="guardagent-fixtures-") as temp_dir:
            fixture_workspace = Path(temp_dir) / "workspace"
            fixture_workspace.mkdir()
            engine = PolicyEngine(candidate, fixture_workspace, resolve_dns=False)
            for path in sorted(fixtures_root.rglob("*.json")):
                try:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    event = GuardEvent.model_validate(document["event"])
                    decision = engine.decide(event)
                    proposed = decision.would_decide or decision.decision
                    expected = document["expected"]
                    failures = []
                    if proposed.value != expected["decision"]:
                        failures.append(f"decision {proposed.value} != {expected['decision']}")
                    if decision.risk != expected["risk"]:
                        failures.append(f"risk {decision.risk} != {expected['risk']}")
                    if not set(expected.get("rule_ids", [])) <= set(decision.rule_ids):
                        failures.append("missing expected rules")
                    results.append({"fixture": str(path.relative_to(fixtures_root)), "passed": not failures, "failures": failures, "actual": decision.model_dump(mode="json")})
                except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                    results.append({"fixture": str(path.relative_to(fixtures_root)), "passed": False, "failures": [str(exc)]})
        return {"source": "fixtures", "passed": all(item.get("passed", False) for item in results), "total": len(results), "failed": sum(not item.get("passed", False) for item in results), "results": results}

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                if not text.endswith("\n"):
                    handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # Windows does not support opening directories this way; the file
                # itself has already been flushed before the atomic replacement.
                pass
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _apply_policy(self, candidate: Any) -> None:
        self.policy = candidate
        self.engine = PolicyEngine(candidate, self.settings.workspace)
        self.store.secret_patterns = self.engine.secret_patterns
        self.correlation = self._create_correlation(candidate.document)
        self._restore_recent_state()

    def publish_policy(
        self, text: str, expected_digest: str, operator: str,
        comment: str = "", confirmation: str | None = None,
    ) -> dict[str, Any]:
        candidate = self.loader.parse(text, self.settings.policy_path)
        with self._policy_lock:
            if expected_digest != self.policy.digest:
                raise PolicyValidationError("policy digest conflict; reload the current policy before publishing")
            if candidate.mode == "enforce" and self.policy.mode != "enforce" and confirmation != "ENFORCE":
                raise PolicyValidationError("publishing enforce mode requires confirmation ENFORCE")
            old_text = self.settings.policy_path.read_text(encoding="utf-8")
            old_policy = self.policy
            revision_id = str(uuid4())
            snapshot_id = str(uuid4())
            try:
                self._atomic_write(self.settings.policy_path, text)
                loaded = self.loader.load(self.settings.policy_path)
                self._apply_policy(loaded)
                self.store.record_policy_revision(
                    snapshot_id, old_policy.digest, None, old_policy.mode, operator,
                    "Automatic pre-publish snapshot", old_text, "snapshot",
                )
                self.store.record_policy(candidate.digest, candidate.document.get("version"), str(self.settings.policy_path), candidate.document, operator)
                self.store.record_policy_revision(revision_id, candidate.digest, expected_digest, candidate.mode, operator, comment, text, "published")
                self.store.record_operator_action("policy.publish", operator, "policy", revision_id, {"from": expected_digest, "to": candidate.digest, "mode": candidate.mode})
            except Exception as exc:
                rollback_error: Exception | None = None
                try:
                    self._atomic_write(self.settings.policy_path, old_text)
                except Exception as rollback_exc:  # preserve the in-memory safe policy even if disk recovery fails
                    rollback_error = rollback_exc
                self._apply_policy(old_policy)
                try:
                    self.store.mark_policy_revision_result(revision_id, "rolled_back")
                    self.store.record_operator_action(
                        "policy.publish_failed", operator, "policy", candidate.digest,
                        {"from": expected_digest, "error": str(exc)[:1000], "rollback_error": str(rollback_error)[:1000] if rollback_error else None},
                    )
                except Exception:
                    pass
                if rollback_error is not None:
                    raise PolicyValidationError(f"policy publish failed and disk rollback failed: {rollback_error}") from exc
                raise
        self._emit("policy.reloaded", {"digest": candidate.digest, "mode": candidate.mode, "revision_id": revision_id})
        return {"revision_id": revision_id, "digest": candidate.digest, "mode": candidate.mode}

    def restore_policy_revision(self, revision_id: str, expected_digest: str, operator: str, confirmation: str | None = None) -> dict[str, Any]:
        revision = self.store.get_policy_revision(revision_id)
        if revision is None:
            raise PolicyValidationError("policy revision not found")
        result = self.publish_policy(
            revision["raw_text"], expected_digest, operator,
            comment=f"Restore revision {revision_id}", confirmation=confirmation,
        )
        self.store.record_operator_action(
            "policy.restore", operator, "policy_revision", revision_id,
            {"from": expected_digest, "to": result["digest"], "published_revision": result["revision_id"]},
        )
        return result

    def reload_policy(self, operator: str = "local-operator") -> dict[str, Any]:
        candidate = self.loader.load(self.settings.policy_path)
        with self._policy_lock:
            self._apply_policy(candidate)
        self.store.record_policy(candidate.digest, candidate.document.get("version"), str(candidate.source), candidate.document, operator)
        self.store.record_operator_action("policy.reload", operator, "policy", candidate.digest, {"mode": candidate.mode})
        self._emit("policy.reloaded", {"digest": candidate.digest, "mode": candidate.mode})
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
