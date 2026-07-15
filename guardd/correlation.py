from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from guardd.models.events import GuardEvent
from guardd.security import contains_sensitive_path, digest_payload


@dataclass
class SessionState:
    calls: deque[tuple[datetime, str]] = field(default_factory=lambda: deque(maxlen=20))
    call_times: deque[datetime] = field(default_factory=deque)
    sensitive_reads: deque[tuple[datetime, str]] = field(default_factory=lambda: deque(maxlen=20))
    failures: Counter[str] = field(default_factory=Counter)
    denied_signatures: deque[tuple[datetime, str]] = field(default_factory=lambda: deque(maxlen=20))
    read_bytes: int = 0
    write_bytes: int = 0
    delete_bytes: int = 0
    upload_bytes: int = 0
    subagents: int = 0
    max_subagent_depth: int = 0
    risk_score: int = 0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelationEngine:
    def __init__(self, tool_budget: int = 200, repeat_limit: int = 5, subagent_limit: int = 3, file_limit: int = 100, byte_limit: int = 50_000_000, delete_ratio_limit: float = 0.5, session_limit: int = 1000):
        self.states: dict[str, SessionState] = {}
        self.tool_budget = tool_budget
        self.repeat_limit = repeat_limit
        self.subagent_limit = subagent_limit
        self.file_limit = file_limit
        self.byte_limit = byte_limit
        self.delete_ratio_limit = delete_ratio_limit
        self.session_limit = session_limit
        self.sender_scores: dict[str, int] = {}

    def _state(self, session_key: str) -> SessionState:
        state = self.states.get(session_key)
        if state is None:
            if len(self.states) >= self.session_limit:
                oldest = min(self.states, key=lambda key: self.states[key].last_seen)
                self.states.pop(oldest, None)
            state = SessionState(call_times=deque(maxlen=self.tool_budget + 1))
            self.states[session_key] = state
        state.last_seen = datetime.now(timezone.utc)
        return state

    def evaluate(self, event: GuardEvent) -> list[dict[str, Any]]:
        state = self._state(event.session_key)
        now = datetime.now(timezone.utc)
        signature = self._signature(event)
        matches: list[dict[str, Any]] = []
        while state.call_times and now - state.call_times[0] > timedelta(minutes=10):
            state.call_times.popleft()
        recent_count = len(state.call_times)
        repeat_count = sum(1 for at, item in state.calls if item == signature and now - at <= timedelta(minutes=1))
        actions = set(event.derived.get("actions", []))
        outbound = bool(actions & {"external_send", "network_write", "remote_write"})
        recent_sensitive = [(at, path) for at, path in state.sensitive_reads if now - at <= timedelta(minutes=10)]
        if outbound and recent_sensitive:
            matches.append(self._rule("CORRELATION-EXFIL-001", "DENY", "critical", "Sensitive data was read within 10 minutes before an outbound action", 2000))
        if recent_count >= self.tool_budget:
            matches.append(self._rule("BUDGET-TOOLS-001", "REQUIRE_APPROVAL", "high", "Session tool-call budget exceeded", 1200))
        if repeat_count >= self.repeat_limit:
            matches.append(self._rule("LOOP-REPEAT-001", "DENY", "high", "The same action is repeating rapidly", 1300))
        if state.subagents >= self.subagent_limit or int(event.params.get("depth", 0) or 0) > self.subagent_limit:
            matches.append(self._rule("SUBAGENT-LIMIT-001", "DENY", "high", "Subagent count or recursion depth exceeded", 1300))
        metrics = event.derived.get("file_metrics", {})
        changed = max(int(metrics.get("file_count", 0) or 0), int(event.params.get("file_count", event.params.get("files_count", 0)) or 0))
        total_bytes = int(metrics.get("total_bytes", 0) or 0)
        delete_ratio = float(metrics.get("delete_ratio", 0.0) or 0.0)
        if changed > self.file_limit or total_bytes > self.byte_limit or (changed >= 20 and delete_ratio > self.delete_ratio_limit):
            matches.append(self._rule("BULK-FILES-001", "REQUIRE_APPROVAL", "high", "Bulk file count, bytes, or deletion ratio exceeds a configured threshold", 1200))
        if any(now - at <= timedelta(minutes=10) for at, denied in state.denied_signatures if denied != signature) and event.derived.get("dynamic_eval"):
            matches.append(self._rule("DENIAL-EVASION-001", "DENY", "critical", "A denied action was retried using dynamic or encoded execution", 2100))
        state.calls.append((now, signature))
        state.call_times.append(now)
        return matches

    def record_result(self, event: GuardEvent, success: bool, bytes_count: int = 0) -> None:
        state = self._state(event.session_key)
        signature = self._signature(event)
        if not success:
            state.failures[signature] += 1
        paths = event.derived.get("paths", [])
        if "read" in event.derived.get("actions", []):
            state.read_bytes += bytes_count
            for path in paths:
                if path.get("path_group") == "sensitive_read_denied" or contains_sensitive_path(path.get("resolved", "")):
                    state.sensitive_reads.append((datetime.now(timezone.utc), path.get("resolved", "unknown")))
        if set(event.derived.get("actions", [])) & {"write", "delete"}:
            state.write_bytes += bytes_count
        if set(event.derived.get("actions", [])) & {"external_send", "network_write"}:
            state.upload_bytes += bytes_count

    def record_denial(self, event: GuardEvent) -> None:
        self._state(event.session_key).denied_signatures.append((datetime.now(timezone.utc), self._signature(event)))

    def record_decision(self, event: GuardEvent, risk: str) -> None:
        weight = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}.get(risk, 3)
        state = self._state(event.session_key)
        state.risk_score = min(10_000, state.risk_score + weight)
        sender = event.origin.sender_id
        if sender:
            if sender not in self.sender_scores and len(self.sender_scores) >= self.session_limit:
                self.sender_scores.pop(next(iter(self.sender_scores)))
            self.sender_scores[sender] = min(10_000, self.sender_scores.get(sender, 0) + weight)

    def session_event(self, event: GuardEvent) -> None:
        state = self._state(event.session_key)
        if event.event_type == "subagent.spawned":
            state.subagents += 1
            state.max_subagent_depth = max(state.max_subagent_depth, int(event.params.get("depth", 1)))
        elif event.event_type == "subagent.ended":
            state.subagents = max(0, state.subagents - 1)
        elif event.event_type == "session.end":
            self.states.pop(event.session_key, None)

    def restore_event(self, event: GuardEvent, successful_read: bool = False) -> None:
        state = self._state(event.session_key)
        occurred = event.occurred_at.astimezone(timezone.utc)
        state.calls.append((occurred, self._signature(event)))
        state.call_times.append(occurred)
        if successful_read:
            for path in event.derived.get("paths", []):
                if path.get("path_group") == "sensitive_read_denied" or contains_sensitive_path(path.get("resolved", "")):
                    state.sensitive_reads.append((occurred, path.get("resolved", "unknown")))
        if event.event_type == "subagent.spawned":
            state.subagents += 1
        elif event.event_type == "subagent.ended":
            state.subagents = max(0, state.subagents - 1)

    def _signature(self, event: GuardEvent) -> str:
        return digest_payload({
            "tool": event.tool.name if event.tool else None,
            "commands": event.derived.get("commands", []),
            "paths": [item.get("resolved") for item in event.derived.get("paths", [])],
            "hosts": [item.get("host") for item in event.derived.get("network_targets", [])],
        })

    @staticmethod
    def _rule(rule_id: str, decision: str, risk: str, reason: str, priority: int) -> dict[str, Any]:
        return {"id": rule_id, "decision": decision, "risk": risk, "reason": reason, "priority": priority}
