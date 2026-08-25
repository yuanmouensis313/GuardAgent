from __future__ import annotations

from typing import Any

from guardd.llm.models import (
    ReviewCommandSummary,
    ReviewEventSummary,
    ReviewLocalSignals,
    ReviewObjective,
    ReviewSubject,
    ReviewTargetSummary,
    SafetyMemorySnapshot,
    SafetyReviewInput,
)
from guardd.models.decisions import Decision
from guardd.models.events import GuardEvent
from guardd.security import hmac_digest_payload, sanitize


_SAFE_ARG_TOKENS = {
    "add", "apply", "build", "checkout", "clone", "commit", "diff", "fetch",
    "install", "list", "log", "pull", "push", "read", "remove", "restore",
    "run", "search", "show", "status", "test", "update", "write",
}


class SafetyReviewContextBuilder:
    def __init__(
        self,
        hmac_key: bytes,
        *,
        max_commands: int = 10,
        max_targets: int = 100,
    ):
        self.hmac_key = hmac_key
        self.max_commands = max(1, min(max_commands, 50))
        self.max_targets = max(1, min(max_targets, 500))

    def build(
        self,
        event: GuardEvent,
        base_decision: Decision,
        memory: SafetyMemorySnapshot,
        *,
        objective_summary: str | None = None,
        subject: ReviewSubject | None = None,
    ) -> SafetyReviewInput:
        task_context = event.derived.get("task_policy")
        task_context = task_context if isinstance(task_context, dict) else {}
        content_context = event.derived.get("content_inspection")
        content_context = content_context if isinstance(content_context, dict) else {}
        commands = [
            self._command_summary(item)
            for item in event.derived.get("commands", [])[: self.max_commands]
            if isinstance(item, dict)
        ]
        paths = [
            ReviewTargetSummary(
                target_id=hmac_digest_payload(
                    {"kind": "path", "value": str(item.get("resolved") or item.get("raw") or "")},
                    self.hmac_key,
                ),
                classification=str(item.get("path_group") or "unknown")[:128],
                access=str(item.get("access") or "")[:64] or None,
            )
            for item in event.derived.get("paths", [])[: self.max_targets]
            if isinstance(item, dict)
        ]
        networks = [
            ReviewTargetSummary(
                target_id=hmac_digest_payload(
                    {"kind": "network", "value": str(item.get("host") or item.get("raw") or "")},
                    self.hmac_key,
                ),
                classification=str(item.get("classification") or "unknown")[:128],
                direction=str(item.get("direction") or "")[:64] or None,
            )
            for item in event.derived.get("network_targets", [])[: self.max_targets]
            if isinstance(item, dict)
        ]
        summary, _ = sanitize(objective_summary or "No active task objective")
        summary_text = str(summary).strip()[:512] or "Task objective withheld after sanitization"
        rule_ids = list(dict.fromkeys(base_decision.rule_ids))[:200]
        correlation_rule_ids = [
            rule_id for rule_id in rule_ids
            if rule_id.startswith(("CORRELATION-", "BUDGET-", "LOOP-", "DENIAL-", "SUBAGENT-", "FILE-BUDGET-"))
        ]
        inferred_subject = (
            ReviewSubject.MESSAGE_SEND
            if event.event_type.startswith("message") or "external_send" in event.derived.get("actions", [])
            else ReviewSubject.TOOL_CALL
        )
        return SafetyReviewInput(
            subject=subject or inferred_subject,
            objective=ReviewObjective(
                summary=summary_text,
                task_policy_digest=base_decision.task_policy_digest or task_context.get("digest"),
            ),
            event=ReviewEventSummary(
                event_type=event.event_type[:128],
                tool_name=(event.tool.name if event.tool else "unknown")[:256],
                tool_kind=(event.tool.kind if event.tool else "unknown")[:128],
                normalized_actions=sorted(set(str(item) for item in event.derived.get("actions", [])))[:50],
                command_summaries=commands,
                path_targets=paths,
                network_targets=networks,
                data_classification=sorted(set(event.data_classification))[:100],
            ),
            local_signals=ReviewLocalSignals(
                base_decision=base_decision.decision.value,
                risk=base_decision.risk,
                rule_ids=rule_ids,
                task_verdict=base_decision.task_policy_verdict or task_context.get("verdict"),
                correlation_rule_ids=correlation_rule_ids,
                content_verdict=str(content_context.get("verdict")) if content_context.get("verdict") else None,
            ),
            memory=memory,
            trust_labels={
                "objective": "trusted_user_input_summary",
                "event_params": "agent_proposed_summary",
                "external_content": "not_included",
                "memory": "guardd_derived",
            },
        )

    @staticmethod
    def _command_summary(command: dict[str, Any]) -> ReviewCommandSummary:
        argv_categories: list[str] = []
        for raw in command.get("argv", [])[:20]:
            value = str(raw).strip().lower()
            if value in _SAFE_ARG_TOKENS:
                argv_categories.append(value)
            elif value.startswith("-"):
                argv_categories.append("<flag>")
            elif "://" in value:
                argv_categories.append("<url>")
            elif "/" in value or "\\" in value:
                argv_categories.append("<path>")
            elif value:
                argv_categories.append("<arg>")
        return ReviewCommandSummary(
            executable=str(command.get("executable") or "")[:128],
            argv_categories=argv_categories,
            dynamic_eval=bool(command.get("dynamic_eval")),
            parse_failed=bool(command.get("parse_failed")),
            shell_features=sorted(set(str(item) for item in command.get("shell_features", [])))[:50],
        )
