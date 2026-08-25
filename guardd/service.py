from __future__ import annotations

import json
import sqlite3
import threading
import difflib
import os
import tempfile
from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

from guardd.agents import SafetyReviewAgent, TaskPolicyAgent
from guardd.approvals import ApprovalManager
from guardd.audit import AuditStore
from guardd.config import Settings
from guardd.correlation import CorrelationEngine
from guardd.inspections import (
    InspectionConfirmationRequest, InspectionError, InspectionManager, McpDescriptorInspectionRequest,
    SkillInspectionRequest,
)
from guardd.llm import (
    CompatibleHttpProvider,
    DecisionFusionEngine,
    LLMProvider,
    PromptRegistry,
    ReviewMode,
    ReviewTrigger,
    SafetyReviewContextBuilder,
    SafetyReviewValidator,
)
from guardd.llm.jobs import ReviewTriggerPolicy
from guardd.models.decisions import Decision, DecisionKind
from guardd.models.events import GuardEvent, ToolResultEvent
from guardd.policy import PolicyEngine, PolicyLoader, PolicyValidationError
from guardd.security import SANITIZATION_PATTERN_DIGEST, digest_payload, ensure_hmac_key, sanitize
from guardd.sanitization import SanitizationEventRequest
from guardd.task_policy import TaskPolicyError, TaskPolicyManager, TaskPolicyStatus
from guardd.task_policy.compiler import TaskPolicyCompiler, TaskPolicyProposalValidator
from guardd.task_policy.hybrid_synthesizer import TrustedTaskContextBuilder


class GuardService:
    def __init__(self, settings: Settings, llm_provider: LLMProvider | None = None):
        self.settings = settings
        self.loader = PolicyLoader()
        self.policy = self.loader.load(settings.policy_path)
        self.engine = PolicyEngine(self.policy, settings.workspace)
        self.store = AuditStore(settings.db_path, settings.emergency_log_path, self.engine.secret_patterns)
        self.hmac_key = ensure_hmac_key(settings.hmac_key_path)
        self.inspections = InspectionManager(
            self.store, self.hmac_key, self.policy.digest,
        )
        if settings.audit_retention_days > 0:
            retention = self.store.purge_before(
                (datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)).isoformat()
            )
            if any(retention.values()):
                self.store.record_operator_action("retention.purge", "startup", "audit", detail=retention)
        self.approvals = ApprovalManager(
            self.store,
            settings.approval_ttl_seconds,
            review_mode=settings.llm_review_mode,
            review_deny_confidence_threshold=settings.llm_review_deny_confidence_threshold,
        )
        self.correlation = self._create_correlation(self.policy.document)
        self.task_policies = TaskPolicyManager(
            self.store,
            settings.workspace,
            settings.hmac_key_path,
            self.policy.digest,
            mode=settings.task_policy_mode,
            ttl_minutes=settings.task_policy_ttl_minutes,
            out_of_scope=settings.task_policy_out_of_scope,
        ) if settings.task_policy_enabled else None
        self.review_agent: SafetyReviewAgent | None = None
        self.task_policy_agent: TaskPolicyAgent | None = None
        self.llm_provider: LLMProvider | None = None
        self.review_trigger = ReviewTriggerPolicy(settings.llm_review_sample_allow_rate)
        self.review_fusion = DecisionFusionEngine(
            deny_confidence_threshold=settings.llm_review_deny_confidence_threshold,
            approval_confidence_threshold=settings.llm_review_approval_confidence_threshold,
        )
        self.review_context_builder = SafetyReviewContextBuilder(self.hmac_key)
        if settings.llm_enabled:
            api_key = os.getenv(settings.llm_api_key_env, "")
            provider_host = urlsplit(settings.llm_base_url or "").hostname
            if (
                llm_provider is None
                and not api_key
                and provider_host not in {"127.0.0.1", "localhost", "::1"}
            ):
                raise ValueError(f"{settings.llm_api_key_env} is required for a remote LLM provider")
            provider = llm_provider or CompatibleHttpProvider(
                settings.llm_base_url or "",
                api_key or "local-no-key",
                connect_timeout_ms=settings.llm_connect_timeout_ms,
                max_output_bytes=settings.llm_max_output_bytes,
            )
            self.llm_provider = provider
        if self.llm_provider is not None and settings.llm_review_mode != "disabled":
            self.review_agent = SafetyReviewAgent(
                store=self.store,
                provider=self.llm_provider,
                model=settings.llm_model or "",
                prompt=PromptRegistry().load("safety-review", "1"),
                validator=SafetyReviewValidator(self.engine.secret_patterns),
                base_policy_digest=self.policy.digest,
                request_timeout_ms=settings.llm_request_timeout_ms,
                max_input_bytes=settings.llm_max_input_bytes,
                max_output_tokens=settings.llm_max_output_tokens,
                max_concurrency=settings.llm_max_concurrency,
                queue_capacity=settings.llm_queue_capacity,
                cache_ttl_minutes=settings.llm_cache_ttl_minutes,
                circuit_breaker_failures=settings.llm_circuit_breaker_failures,
                circuit_breaker_cooldown_seconds=settings.llm_circuit_breaker_cooldown_seconds,
                review_mode=settings.llm_review_mode,
                deny_confidence_threshold=settings.llm_review_deny_confidence_threshold,
            )
            self.review_agent.start()
        if (
            self.llm_provider is not None
            and settings.task_policy_synthesizer == "hybrid"
            and self.task_policies is not None
        ):
            self.task_policy_agent = TaskPolicyAgent(
                store=self.store,
                provider=self.llm_provider,
                model=settings.llm_model or "",
                prompt=PromptRegistry().load("task-policy", "1"),
                validator=TaskPolicyProposalValidator(self.engine.secret_patterns),
                compiler=TaskPolicyCompiler(),
                on_compiled=self._accept_hybrid_policy,
                request_timeout_ms=settings.task_policy_model_timeout_ms,
                max_input_bytes=settings.llm_max_input_bytes,
                max_output_tokens=max(settings.llm_max_output_tokens, 2000),
                max_concurrency=1,
                queue_capacity=max(1, settings.llm_queue_capacity // 2),
                circuit_breaker_failures=settings.llm_circuit_breaker_failures,
                circuit_breaker_cooldown_seconds=settings.llm_circuit_breaker_cooldown_seconds,
            )
            self.task_policy_agent.start()
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
                task_matches = self.task_policies.evaluate(event) if self.task_policies else []
                inspection_matches = self._inspection_matches(event)
                decision = self.engine.decide(event, [*correlations, *inspection_matches, *task_matches])
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
        self._apply_llm_review(event, decision)
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

    def _apply_llm_review(self, event: GuardEvent, decision: Decision) -> None:
        mode = ReviewMode(self.settings.llm_review_mode)
        if mode == ReviewMode.DISABLED or self.review_agent is None:
            return
        decision.base_decision = decision.decision
        decision.decision_sources.append({
            "source": "deterministic",
            "digest": self.policy.digest,
            "decision": decision.decision.value,
        })
        trigger = self.review_trigger.evaluate(decision, decision.parameter_digest)
        if trigger == ReviewTrigger.SKIP:
            decision.review_status = "skipped"
            return
        try:
            active_policy = (
                self.task_policies.get(event.session_key, TaskPolicyStatus.ACTIVE)
                if self.task_policies else None
            )
            objective_summary = active_policy.objective.summary if active_policy else None
            memory = self.correlation.safety_memory(
                event.session_key,
                self.hmac_key,
                active_task_policy_digest=decision.task_policy_digest,
            )
            input_document = self.review_context_builder.build(
                event,
                decision,
                memory,
                objective_summary=objective_summary,
            )
            cached = self.review_agent.get_cached(input_document)
            if cached is not None:
                decision.review_id = UUID(cached["review_id"])
                decision.review_status = "completed"
                decision.review_verdict = cached["verdict"]
                decision.review_digest = cached["result_digest"]
                decision.decision_sources.append({
                    "source": "llm_review",
                    "digest": cached["result_digest"],
                    "decision": cached["verdict"],
                })
                override = self.store.get_active_llm_review_override(
                    cached["review_id"],
                    decision.parameter_digest,
                )
                if override is not None and mode == ReviewMode.ENFORCE_TIGHTEN:
                    self._tighten_for_review_override(decision, cached, override)
                else:
                    self.review_fusion.fuse(decision, trigger, cached, mode)
                return
            reference = self.review_agent.enqueue(
                input_document,
                subject_id=str(event.event_id),
                priority={"info": 0, "low": 10, "medium": 30, "high": 70, "critical": 100}.get(decision.risk, 30),
            )
            if reference is None:
                decision.review_status = "queue_full"
                if mode == ReviewMode.ENFORCE_TIGHTEN and trigger == ReviewTrigger.REVIEW_REQUIRED:
                    self._tighten_for_pending_review(decision, "LLM review queue is full")
                return
            decision.review_id = reference.review_id
            decision.review_status = reference.status.value
            if (
                mode == ReviewMode.ENFORCE_TIGHTEN
                and trigger == ReviewTrigger.REVIEW_REQUIRED
                and decision.decision != DecisionKind.OBSERVE
            ):
                self._tighten_for_pending_review(decision, "Required semantic review is pending")
        except Exception as exc:
            decision.review_status = "degraded"
            self.store.incident(
                "high",
                "llm_review_enqueue",
                "LLM review could not be scheduled",
                {"event_id": str(event.event_id), "error_type": type(exc).__name__},
            )
            if (
                mode == ReviewMode.ENFORCE_TIGHTEN
                and trigger == ReviewTrigger.REVIEW_REQUIRED
                and decision.decision != DecisionKind.OBSERVE
            ):
                self._tighten_for_pending_review(decision, "Required semantic review is unavailable")

    @staticmethod
    def _tighten_for_pending_review(decision: Decision, reason: str) -> None:
        if decision.decision == DecisionKind.DENY:
            return
        if decision.decision != DecisionKind.REQUIRE_APPROVAL:
            decision.decision = DecisionKind.REQUIRE_APPROVAL
        if "LLM-REVIEW-PENDING-001" not in decision.rule_ids:
            decision.rule_ids.append("LLM-REVIEW-PENDING-001")
        decision.risk = "high" if decision.risk in {"info", "low", "medium"} else decision.risk
        decision.reason = f"{decision.reason}; {reason}"
        decision.remediation = "Wait for semantic review to complete, then retry the exact bound action"

    @staticmethod
    def _tighten_for_review_override(
        decision: Decision,
        review: dict[str, Any],
        override: dict[str, Any],
    ) -> None:
        proposed = decision.would_decide or decision.decision
        if proposed == DecisionKind.DENY:
            return
        if decision.decision == DecisionKind.OBSERVE:
            decision.would_decide = DecisionKind.REQUIRE_APPROVAL
        else:
            decision.decision = DecisionKind.REQUIRE_APPROVAL
        if "LLM-REVIEW-OVERRIDE-APPROVAL-001" not in decision.rule_ids:
            decision.rule_ids.append("LLM-REVIEW-OVERRIDE-APPROVAL-001")
        decision.risk = "high" if decision.risk in {"info", "low", "medium"} else decision.risk
        decision.reason = (
            f"{decision.reason}; semantic deny {review['review_id']} was locally overridden "
            f"for this exact parameter digest; one-time operator approval remains required"
        )
        decision.remediation = (
            "Independently verify the locally audited override and approve only this exact action once"
        )
        decision.decision_sources.append({
            "source": "local_security_override",
            "digest": digest_payload({
                "override_id": override["override_id"],
                "review_id": override["review_id"],
                "parameter_digest": override["parameter_digest"],
            }),
            "decision": "REQUIRE_APPROVAL",
        })

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

    def override_review_block(
        self,
        approval_id: UUID,
        *,
        parameter_digest: str,
        operator: str,
        reason: str,
        confirmation: str,
    ) -> dict[str, Any]:
        if confirmation != "OVERRIDE_LLM_DENY":
            raise ValueError("security override requires confirmation OVERRIDE_LLM_DENY")
        result = self.approvals.override_review_block(
            approval_id,
            parameter_digest=parameter_digest,
            operator=operator,
            reason=reason,
        )
        self.store.record_operator_action(
            "approval.review_override",
            operator,
            "approval",
            str(approval_id),
            {
                "event_id": result["event_id"],
                "blocking_review_id": result["blocking_review_id"],
                "parameter_digest": result["parameter_digest"],
                "reason": result["override_reason"],
            },
        )
        self._emit("approval.review_override", {"approval_id": str(approval_id)})
        return result

    def request_event_review(self, event_id: UUID, operator: str) -> dict[str, Any]:
        if self.review_agent is None:
            raise ValueError("LLM review is disabled")
        detail = self.store.get_event_detail(str(event_id))
        if detail is None or not detail.get("decision_id"):
            raise ValueError("event decision not found")
        try:
            event = GuardEvent.model_validate(detail["event"])
            decision = Decision(
                decision_id=UUID(detail["decision_id"]),
                event_id=event_id,
                decision=DecisionKind(detail["decision"]),
                would_decide=DecisionKind(detail["would_decide"]) if detail.get("would_decide") else None,
                risk=detail["risk"],
                rule_ids=detail.get("rule_ids", []),
                reason=detail["reason"],
                effective_mode=detail["mode"],
                parameter_digest=detail["parameter_digest"],
                sanitized_params=event.params,
                task_policy_digest=detail.get("task_policy_digest"),
                task_policy_revision=detail.get("task_policy_revision"),
                task_policy_verdict=detail.get("task_policy_verdict"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("stored event decision cannot be reviewed") from exc
        active_policy = (
            self.task_policies.get(event.session_key, TaskPolicyStatus.ACTIVE)
            if self.task_policies else None
        )
        memory = self.correlation.safety_memory(
            event.session_key,
            self.hmac_key,
            active_task_policy_digest=decision.task_policy_digest,
        )
        input_document = self.review_context_builder.build(
            event,
            decision,
            memory,
            objective_summary=active_policy.objective.summary if active_policy else None,
        )
        cached = self.review_agent.get_cached(input_document)
        if cached is not None:
            result = {"review_id": cached["review_id"], "status": "completed", "cache_hit": True}
        else:
            reference = self.review_agent.enqueue(
                input_document,
                subject_id=str(event_id),
                priority=100,
            )
            if reference is None:
                raise ValueError("LLM review queue is full")
            result = reference.model_dump(mode="json")
        self.store.record_operator_action(
            "llm_review.request",
            operator,
            "event",
            str(event_id),
            {"review_id": str(result["review_id"]), "cache_hit": bool(result.get("cache_hit"))},
        )
        self._emit("llm_review.queued", {"event_id": str(event_id), "review_id": str(result["review_id"])})
        return result

    def _inspection_matches(self, event: GuardEvent) -> list[dict[str, Any]]:
        identity = event.content_identity
        if not self.settings.content_inspection_enabled or self.settings.content_inspection_mode == "disabled":
            return []
        if identity is None or identity.kind == "native":
            return []
        inspection_digest = identity.artifact_digest or identity.digest
        if not inspection_digest:
            return [{
                "id": "CONTENT-INSPECTION-MISSING-001", "decision": "REQUIRE_APPROVAL", "risk": "high",
                "reason": "Skill/MCP content has no digest-bound inspection identity", "priority": 1900,
            }]
        try:
            verdict = self.inspections.effective_decision(inspection_digest, event.session_key)
        except InspectionError:
            verdict = "STALE"
        event.derived["content_inspection"] = {
            "kind": identity.kind, "name": identity.name, "digest": identity.digest,
            "artifact_digest": inspection_digest, "verdict": verdict,
        }
        if self.settings.content_inspection_mode == "observe":
            return []
        if verdict == "ALLOW":
            return []
        if verdict == "REQUIRE_APPROVAL":
            decision = "REQUIRE_APPROVAL"
        else:
            decision = "DENY"
        return [{
            "id": f"CONTENT-INSPECTION-{verdict}-001", "decision": decision,
            "risk": "critical" if verdict in {"DENY", "QUARANTINE"} else "high",
            "reason": f"{identity.kind} content inspection verdict is {verdict}", "priority": 1950,
        }]

    def tool_result(self, result: ToolResultEvent) -> None:
        self.store.record_tool_result(result)
        event = self._events.get(result.event_id)
        if event:
            size = len(str(result.output).encode("utf-8")) if result.output is not None else 0
            self.correlation.record_result(event, result.success, size)
        self._emit("event.tool_result", {"event_id": str(result.event_id), "success": result.success})

    def sanitization_event(self, event: SanitizationEventRequest) -> dict[str, Any]:
        self.store.record_sanitization_event(event)
        self._emit("sanitization.recorded", {
            "sanitizer_event_id": event.sanitizer_event_id,
            "session_key": event.session_key,
            "direction": event.direction,
            "blocked": event.blocked,
        })
        return {"status": "recorded", "sanitizer_event_id": event.sanitizer_event_id}

    def inspect_skill(self, request: SkillInspectionRequest) -> dict[str, Any]:
        result = self.inspections.inspect_skill(request)
        self.store.record_operator_action(
            "inspection.skill", "openclaw", "content_artifact", result["content_digest"],
            {"name": result["canonical_name"], "decision": result["verdict"]["decision"], "cache_hit": result["cache_hit"]},
        )
        self._emit("inspection.updated", {
            "content_digest": result["content_digest"], "kind": "skill",
            "decision": result["verdict"]["decision"],
        })
        return result

    def inspect_mcp(self, request: McpDescriptorInspectionRequest) -> dict[str, Any]:
        result = self.inspections.inspect_mcp(request)
        self.store.record_operator_action(
            "inspection.mcp", "mcp-proxy", "content_artifact", result["content_digest"],
            {"name": result["canonical_name"], "decision": result["verdict"]["decision"], "cache_hit": result["cache_hit"]},
        )
        self._emit("inspection.updated", {
            "content_digest": result["content_digest"], "kind": "mcp",
            "decision": result["verdict"]["decision"],
        })
        return result

    def confirm_inspection(self, content_digest: str, request: InspectionConfirmationRequest) -> dict[str, Any]:
        result = self.inspections.confirm(content_digest, request)
        self.store.record_operator_action(
            f"inspection.{request.decision}", request.operator, "content_artifact", content_digest,
            {"scope": request.scope, "session_key": request.session_key},
        )
        self._emit("inspection.updated", {"content_digest": content_digest, "decision": request.decision})
        return result

    def session_event(self, event: GuardEvent) -> None:
        event = self.engine.normalize(event)
        self.correlation.session_event(event)
        if self.task_policies and event.event_type == "session.end":
            self.task_policies.close(event.session_key, "session-end")
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
            # Only replay events that originally produced a decision. Lifecycle
            # telemetry is useful in the timeline but is not a policy action.
            # Audit rows intentionally discard raw secrets, so reuse their
            # sanitized normalized evidence instead of attempting to normalize
            # summarized parameters a second time.
            engine = PolicyEngine(candidate, self.settings.workspace)
            events = self.store.replay_events(session_key)
            for raw in events:
                try:
                    event = GuardEvent.model_validate(raw)
                    if "guardd_version" not in event.derived:
                        results.append({"event_id": str(event.event_id), "error": "normalized audit evidence is unavailable"})
                        continue
                    decision = engine.decide(event, [])
                    proposed = decision.would_decide or decision.decision
                    results.append({"event_id": str(event.event_id), "decision": proposed.value, "risk": decision.risk, "rule_ids": decision.rule_ids})
                except (ValueError, KeyError) as exc:
                    results.append({"error": str(exc)})
            return {
                "source": "session", "session_key": session_key,
                "evidence": "recorded_sanitized_normalized",
                "passed": all("error" not in item for item in results), "results": results,
            }

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
        if self.task_policies:
            self.task_policies.update_base_policy_digest(candidate.digest)
        if self.review_agent:
            self.review_agent.update_base_policy_digest(candidate.digest)
            self.review_agent.validator.secret_patterns = self.engine.secret_patterns
        if self.task_policy_agent:
            self.task_policy_agent.validator.secret_patterns = self.engine.secret_patterns
        self.inspections.update_policy_digest(candidate.digest)
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
            "task_policy": {
                "enabled": self.task_policies is not None,
                "mode": self.settings.task_policy_mode,
                "out_of_scope": self.settings.task_policy_out_of_scope,
                "synthesizer": self.settings.task_policy_synthesizer,
                "generation_health": self.task_policy_agent.health() if self.task_policy_agent else None,
            },
            "sanitization": {
                "enabled": self.settings.sanitization_enabled,
                "mode": self.settings.sanitization_mode,
                "max_result_bytes": self.settings.sanitization_max_result_bytes,
            },
            "content_inspection": {
                "enabled": self.settings.content_inspection_enabled,
                "mode": self.settings.content_inspection_mode,
            },
            "llm_review": {
                "enabled": self.review_agent is not None,
                "mode": self.settings.llm_review_mode,
                "health": self.review_agent.health() if self.review_agent else None,
            },
            **self.store.status_counts(),
        }

    def capabilities(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "event_schema_versions": ["1.0", "1.1"],
            "task_policy": {
                "enabled": self.task_policies is not None,
                "api_version": "1.0",
                "synthesizer": self.settings.task_policy_synthesizer,
                "hybrid_generation": self.task_policy_agent is not None,
                "deterministic_fallback": True,
            },
            "sanitization": {
                "enabled": self.settings.sanitization_enabled,
                "mode": self.settings.sanitization_mode,
                "pattern_digest": SANITIZATION_PATTERN_DIGEST,
                "tool_result_persist_required": True,
                "before_message_write_fallback": True,
                "max_result_bytes": self.settings.sanitization_max_result_bytes,
            },
            "content_inspection": {
                "enabled": self.settings.content_inspection_enabled,
                "mode": self.settings.content_inspection_mode,
                "skill": True,
                "skill_install_hook": True,
                "skill_startup_root_scan": True,
                "skill_authoritative_use_identity": False,
                "skill_runtime_identity_required_for_binding": True,
                "mcp_descriptor_registration_hook": False,
                "mcp_proxy_required": True,
                "mcp_proxy_transports": ["stdio"],
                "mcp_unprotected_transports": ["sse", "streamable_http"],
            },
            "llm_review": {
                "enabled": self.review_agent is not None,
                "mode": self.settings.llm_review_mode,
                "schema_version": "1.0",
                "subjects": ["tool_call", "message_send"],
                "async": True,
                "can_loosen_base_policy": False,
            },
        }

    def list_llm_reviews(
        self,
        status: str | None = None,
        session_key: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.store.list_llm_reviews(
            status=status,
            session_key=session_key,
            limit=min(max(limit, 1), 500),
        )

    def get_llm_review(self, review_id: UUID) -> dict[str, Any]:
        item = self.store.get_llm_review(str(review_id))
        if item is None:
            raise ValueError("LLM review not found")
        return item

    def retry_llm_review(self, review_id: UUID, operator: str) -> dict[str, Any]:
        item = self.store.retry_llm_review(str(review_id))
        if item is None:
            raise ValueError("LLM review not found")
        self.store.record_operator_action(
            "llm_review.retry", operator, "llm_review", str(review_id),
            {"status": item.get("status")},
        )
        self._emit("llm_review.queued", {"review_id": str(review_id)})
        return item

    def llm_health(self) -> dict[str, Any]:
        if self.review_agent is None:
            return {"enabled": False, "mode": self.settings.llm_review_mode}
        return {"mode": self.settings.llm_review_mode, **self.review_agent.health()}

    def llm_metrics(self) -> dict[str, Any]:
        return self.store.llm_review_metrics()

    def capture_task_policy(
        self, prompt: str, session_key: str, agent_id: str,
        parent_session_key: str | None = None, origin: Any = None,
    ) -> Any:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        policy = self.task_policies.capture(
            prompt=prompt, session_key=session_key, agent_id=agent_id,
            parent_session_key=parent_session_key,
            origin=origin,
        )
        if (
            self.task_policy_agent is not None
            and policy.status in {TaskPolicyStatus.CANDIDATE, TaskPolicyStatus.REVISION_CANDIDATE}
            and policy.provenance.generator == "deterministic"
        ):
            active = self.task_policies.get(session_key, TaskPolicyStatus.ACTIVE)
            context = TrustedTaskContextBuilder().build(
                prompt=prompt,
                draft=policy,
                origin=origin,
                active_task_summary=active.objective.summary if active else None,
            )
            generation = self.task_policy_agent.enqueue(context, policy)
            if generation is None:
                self.store.incident(
                    "high",
                    "task_policy_generation_queue",
                    "Hybrid task-policy generation queue is full; deterministic candidate retained",
                    {"session_key": session_key, "revision": policy.revision},
                )
            else:
                self._emit("task_policy.generation_queued", {
                    "generation_id": generation["generation_id"],
                    "session_key": session_key,
                    "revision": policy.revision,
                })
        self.store.record_operator_action(
            "task_policy.capture", "openclaw", "task_policy", str(policy.task_policy_id),
            {"session_key": session_key, "revision": policy.revision, "digest": policy.policy_digest, "status": policy.status.value},
        )
        event_name = "task_policy.activated" if policy.status == TaskPolicyStatus.ACTIVE else "task_policy.candidate"
        self._emit(event_name, {
            "task_policy_id": str(policy.task_policy_id), "session_key": session_key,
            "revision": policy.revision, "digest": policy.policy_digest, "status": policy.status.value,
        })
        return policy

    def _accept_hybrid_policy(self, policy: Any, generation_id: str) -> Any:
        if self.task_policies is None:
            return None
        accepted = self.task_policies.accept_hybrid_candidate(policy, generation_id)
        if accepted is not None:
            self._emit("task_policy.hybrid_candidate", {
                "generation_id": generation_id,
                "task_policy_id": str(accepted.task_policy_id),
                "session_key": accepted.session_key,
                "revision": accepted.revision,
                "status": accepted.status.value,
                "digest": accepted.policy_digest,
            })
        return accepted

    def get_task_policy_generation(self, generation_id: UUID) -> dict[str, Any]:
        item = self.store.get_task_policy_generation(str(generation_id))
        if item is None:
            raise TaskPolicyError("task policy generation not found")
        return item

    def list_task_policy_generations(
        self,
        session_key: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.store.list_task_policy_generations(
            session_key=session_key,
            status=status,
            limit=min(max(limit, 1), 500),
        )

    def retry_task_policy_generation(self, generation_id: UUID, operator: str) -> dict[str, Any]:
        item = self.store.retry_task_policy_generation(str(generation_id))
        if item is None:
            raise TaskPolicyError("task policy generation not found")
        self.store.record_operator_action(
            "task_policy_generation.retry", operator, "task_policy_generation", str(generation_id),
            {"status": item.get("status")},
        )
        return item

    def safety_memory(self, session_key: str) -> dict[str, Any]:
        active = (
            self.task_policies.get(session_key, TaskPolicyStatus.ACTIVE)
            if self.task_policies else None
        )
        return self.correlation.safety_memory(
            session_key,
            self.hmac_key,
            active_task_policy_digest=active.policy_digest if active else None,
        ).model_dump(mode="json")

    def get_task_policy(self, session_key: str, status: str | None = None) -> Any:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        parsed = TaskPolicyStatus(status) if status else None
        policy = self.task_policies.get(session_key, parsed)
        if policy is None:
            raise TaskPolicyError("task policy not found")
        return policy

    def get_task_policy_view(self, session_key: str) -> dict[str, Any]:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        return self.task_policies.session_view(session_key)

    def activate_task_policy(
        self, session_key: str, candidate_digest: str,
        expected_active_revision: int | None, operator: str,
    ) -> Any:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        policy = self.task_policies.activate(session_key, candidate_digest, expected_active_revision, operator)
        self.store.record_operator_action(
            "task_policy.activate", operator, "task_policy", str(policy.task_policy_id),
            {"session_key": session_key, "revision": policy.revision, "digest": policy.policy_digest},
        )
        self._emit("task_policy.activated", {
            "task_policy_id": str(policy.task_policy_id), "session_key": session_key,
            "revision": policy.revision, "digest": policy.policy_digest,
        })
        return policy

    def reject_task_policy(self, session_key: str, candidate_digest: str, operator: str) -> Any:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        policy = self.task_policies.reject(session_key, candidate_digest, operator)
        self.store.record_operator_action(
            "task_policy.reject", operator, "task_policy", str(policy.task_policy_id),
            {"session_key": session_key, "revision": policy.revision, "digest": policy.policy_digest},
        )
        self._emit("task_policy.rejected", {
            "task_policy_id": str(policy.task_policy_id), "session_key": session_key,
            "revision": policy.revision,
        })
        return policy

    def revise_task_policy_content(
        self, session_key: str, kind: str, name: str, content_digest: str,
        expected_active_revision: int, operator: str, artifact_digest: str | None = None,
    ) -> Any:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        inspection_digest = artifact_digest or content_digest
        if self.inspections.effective_decision(inspection_digest, session_key) != "ALLOW":
            raise TaskPolicyError("content inspection is not approved for this digest")
        policy = self.task_policies.revise_content(
            session_key, kind, name, content_digest, expected_active_revision,
        )
        self.store.record_operator_action(
            "task_policy.revise_content", operator, "task_policy", str(policy.task_policy_id),
            {"session_key": session_key, "kind": kind, "name": name, "content_digest": content_digest},
        )
        self._emit("task_policy.candidate", {
            "task_policy_id": str(policy.task_policy_id), "session_key": session_key,
            "revision": policy.revision, "digest": policy.policy_digest,
        })
        return policy

    def close_task_policy(self, session_key: str, operator: str) -> dict[str, Any]:
        if self.task_policies is None:
            raise TaskPolicyError("task policy support is disabled")
        closed = self.task_policies.close(session_key, operator)
        self.store.record_operator_action(
            "task_policy.close", operator, "task_policy", session_key, {"closed": closed},
        )
        self._emit("task_policy.closed", {"session_key": session_key, "closed": closed})
        return {"session_key": session_key, "closed": closed}

    def close(self) -> None:
        if self.task_policy_agent:
            self.task_policy_agent.close()
        if self.review_agent:
            self.review_agent.close()
        self.store.close()
