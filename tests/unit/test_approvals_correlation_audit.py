from __future__ import annotations

import copy
import json
import tempfile
import unittest
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from guardd.config import Settings
from guardd.correlation import CorrelationEngine
from guardd.models.events import GuardEvent, ToolDescriptor
from guardd.policy import PolicyEngine, PolicyLoader
from guardd.service import GuardService
from unittest.mock import patch


ROOT = Path(__file__).parents[2]


def enforce_policy(temp: Path) -> Path:
    policy = copy.deepcopy(PolicyLoader().load(ROOT / "policies/default.yaml").document)
    policy["defaults"]["mode"] = "enforce"
    path = temp / "enforce.yaml"
    import yaml
    path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    return path


class ServiceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        settings = Settings(state_dir=self.root / "state", policy_path=enforce_policy(self.root), workspace=self.workspace, approval_ttl_seconds=60)
        self.service = GuardService(settings)

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def event(self, command: str, session: str = "session") -> GuardEvent:
        return GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key=session, tool=ToolDescriptor(name="exec", kind="shell", input_kind="bash"), params={"command": command})


class ApprovalTests(ServiceCase):
    def test_approval_is_single_use_and_parameter_bound(self) -> None:
        event = self.event("git push origin main")
        decision = self.service.decide(event)
        self.assertEqual(decision.decision.value, "REQUIRE_APPROVAL")
        self.assertIsNotNone(decision.approval_id)
        self.service.resolve_approval(decision.approval_id, True, "tester")
        self.assertTrue(self.service.approvals.consume(decision.approval_id, decision.parameter_digest, event))
        self.assertFalse(self.service.approvals.consume(decision.approval_id, decision.parameter_digest, event))

    def test_parameter_digest_change_invalidates_approval(self) -> None:
        event = self.event("git push origin main")
        decision = self.service.decide(event)
        self.service.resolve_approval(decision.approval_id, True, "tester")
        self.assertFalse(self.service.approvals.consume(decision.approval_id, "sha256:changed", event))

    def test_expired_approval_cannot_resolve(self) -> None:
        event = self.event("git push origin main")
        decision = self.service.decide(event)
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with self.service.store._lock, self.service.store._connection:
            self.service.store._connection.execute("UPDATE approvals SET expires_at=? WHERE approval_id=?", (expired, str(decision.approval_id)))
        with self.assertRaises(ValueError):
            self.service.resolve_approval(decision.approval_id, True, "tester")

    def test_denied_approval_then_encoded_variant_is_critical(self) -> None:
        original = self.event("git push origin main", "evasion")
        decision = self.service.decide(original)
        self.service.resolve_approval(decision.approval_id, False, "tester")
        retry = self.event("python -c 'print(1)'", "evasion")
        retry_decision = self.service.decide(retry)
        self.assertEqual(retry_decision.decision.value, "DENY")
        self.assertIn("DENIAL-EVASION-001", retry_decision.rule_ids)


class CorrelationTests(unittest.TestCase):
    def test_sensitive_read_followed_by_send_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            engine = PolicyEngine(PolicyLoader().load(ROOT / "policies/default.yaml"), workspace)
            correlation = CorrelationEngine()
            read_event = GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="cross", tool=ToolDescriptor(name="read"), params={"path": ".env"})
            engine.normalize(read_event)
            correlation.record_result(read_event, True, 100)
            send_event = GuardEvent(event_type="message.before", source="test", agent_id="main", session_key="cross", tool=ToolDescriptor(name="message_send"), params={"content": "hello"})
            engine.normalize(send_event)
            matches = correlation.evaluate(send_event)
            self.assertIn("CORRELATION-EXFIL-001", {item["id"] for item in matches})

    def test_tool_budget_repeat_and_subagent_limits(self) -> None:
        correlation = CorrelationEngine(tool_budget=2, repeat_limit=1, subagent_limit=1)
        event = GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="budget", tool=ToolDescriptor(name="health"))
        event.derived = {"actions": [], "commands": [], "paths": [], "network_targets": []}
        self.assertEqual(correlation.evaluate(event), [])
        second = correlation.evaluate(event)
        self.assertIn("LOOP-REPEAT-001", {item["id"] for item in second})
        third = correlation.evaluate(event)
        self.assertIn("BUDGET-TOOLS-001", {item["id"] for item in third})
        spawn = GuardEvent(event_type="subagent.spawned", source="test", agent_id="main", session_key="budget", params={"depth": 1})
        correlation.session_event(spawn)
        self.assertIn("SUBAGENT-LIMIT-001", {item["id"] for item in correlation.evaluate(event)})


class AuditTests(ServiceCase):
    def test_secret_is_not_stored_in_event_json(self) -> None:
        secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456"
        event = GuardEvent(event_type="message.before", source="test", agent_id="main", session_key="audit", tool=ToolDescriptor(name="message_send"), params={"content": secret})
        self.service.decide(event)
        with self.service.store._lock:
            row = self.service.store._connection.execute("SELECT sanitized_json FROM events WHERE event_id=?", (str(event.event_id),)).fetchone()
        self.assertNotIn(secret, row[0])
        stored = json.loads(row[0])
        self.assertEqual(stored["params"]["content"]["type"], "string")
        self.assertIn("sha256", stored["params"]["content"])

    def test_hash_chain_and_required_tables(self) -> None:
        self.service.decide(self.event("git status", "hash"))
        self.service.decide(self.event("git diff", "hash"))
        with self.service.store._lock:
            rows = self.service.store._connection.execute("SELECT event_hash, previous_hash FROM events ORDER BY rowid").fetchall()
            tables = {row[0] for row in self.service.store._connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(rows[1]["previous_hash"], rows[0]["event_hash"])
        self.assertTrue({"events", "decisions", "rule_matches", "approvals", "tool_results", "sessions", "policy_versions", "service_incidents"} <= tables)
        self.assertEqual(self.service.store.integrity_check(), "ok")

    def test_high_risk_fails_closed_when_audit_write_fails(self) -> None:
        with patch.object(self.service.store, "record_event", side_effect=sqlite3.OperationalError("locked")):
            decision = self.service.decide(self.event("git push origin main", "audit-failure"))
        self.assertEqual(decision.decision.value, "DENY")
        self.assertIn("failed closed", decision.reason)

    def test_normalization_failure_is_never_silently_allowed(self) -> None:
        with patch.object(self.service.engine, "normalize", side_effect=ValueError("bad envelope")):
            decision = self.service.decide(self.event("unknown", "parse-failure"))
        self.assertEqual(decision.decision.value, "REQUIRE_APPROVAL")
        self.assertEqual(decision.risk, "high")
        self.assertIn("NORMALIZATION-ERROR-001", decision.rule_ids)


class RestartAndPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.policy_path = enforce_policy(self.root)
        self.settings = Settings(state_dir=self.root / "state", policy_path=self.policy_path, workspace=self.workspace)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_restart_invalidates_pending_approval_and_restores_recent_calls(self) -> None:
        first = GuardService(self.settings)
        approval_event = GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="restart-approval", tool=ToolDescriptor(name="exec"), params={"command": "git push origin main"})
        approval = first.decide(approval_event)
        for _ in range(5):
            first.decide(GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="restart-loop", tool=ToolDescriptor(name="health")))
        first.close()
        second = GuardService(self.settings)
        try:
            records = second.approvals.list(False)
            record = next(item for item in records if item["approval_id"] == str(approval.approval_id))
            self.assertEqual(record["status"], "invalidated_restart")
            repeated = second.decide(GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="restart-loop", tool=ToolDescriptor(name="health")))
            self.assertEqual(repeated.decision.value, "DENY")
            self.assertIn("LOOP-REPEAT-001", repeated.rule_ids)
        finally:
            second.close()

    def test_invalid_reload_keeps_last_valid_policy(self) -> None:
        service = GuardService(self.settings)
        original = service.policy.digest
        self.policy_path.write_text("version: [invalid", encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                service.reload_policy()
            self.assertEqual(service.policy.digest, original)
        finally:
            service.close()


if __name__ == "__main__":
    unittest.main()
