from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml
import subprocess

from guardd import doctor as doctor_module
from guardd.config import Settings
from guardd.api.ui.auth import UiAuthError, UiAuthManager
from guardd.models.events import GuardEvent, ToolDescriptor
from guardd.policy import PolicyLoader, PolicyValidationError
from guardd.realtime import EventBus
from guardd.service import GuardService


ROOT = Path(__file__).parents[2]


class UiServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        policy = copy.deepcopy(PolicyLoader().load(ROOT / "policies/default.yaml").document)
        policy["defaults"]["mode"] = "enforce"
        self.policy_path = self.root / "policy.yaml"
        self.policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        self.settings = Settings(state_dir=self.root / "state", policy_path=self.policy_path, workspace=self.workspace)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_policy_publish_rolls_back_file_and_memory_when_reload_fails(self) -> None:
        service = GuardService(self.settings)
        original_text = self.policy_path.read_text(encoding="utf-8")
        original_digest = service.policy.digest
        candidate = copy.deepcopy(service.policy.document)
        candidate["budgets"]["same_action_per_minute"] = 1
        candidate_text = yaml.safe_dump(candidate, sort_keys=False)
        try:
            with patch.object(service.loader, "load", side_effect=PolicyValidationError("reload failed")):
                with self.assertRaises(PolicyValidationError):
                    service.publish_policy(candidate_text, original_digest, "test")
            self.assertEqual(self.policy_path.read_text(encoding="utf-8"), original_text)
            self.assertEqual(service.policy.digest, original_digest)
        finally:
            service.close()

    def test_fixture_regression_is_isolated_from_deployed_workspace(self) -> None:
        settings = Settings(
            state_dir=self.root / "regression-state",
            policy_path=self.policy_path,
            workspace=ROOT,
        )
        service = GuardService(settings)
        try:
            result = service.regression_policy(self.policy_path.read_text(encoding="utf-8"))
            self.assertEqual(result["source"], "fixtures")
            self.assertGreaterEqual(result["total"], 30)
            self.assertEqual(result["failed"], 0)
            self.assertTrue(result["passed"])
        finally:
            service.close()

    def test_session_replay_excludes_lifecycle_and_reuses_normalized_evidence(self) -> None:
        service = GuardService(self.settings)
        session_key = "replay-normalized"
        lifecycle = GuardEvent(
            event_type="session.start", source="test", agent_id="main", session_key=session_key,
        )
        action = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=session_key,
            tool=ToolDescriptor(name="exec", kind="shell", input_kind="powershell"),
            params={"command": "git status"},
        )
        try:
            service.session_event(lifecycle)
            original = service.decide(action)
            self.assertIn("GIT-READ-001", original.rule_ids)

            result = service.regression_policy(self.policy_path.read_text(encoding="utf-8"), session_key)

            self.assertTrue(result["passed"])
            self.assertEqual(result["evidence"], "recorded_sanitized_normalized")
            self.assertEqual(len(result["results"]), 1)
            self.assertEqual(result["results"][0]["event_id"], str(action.event_id))
            self.assertEqual(result["results"][0]["decision"], "ALLOW")
            self.assertIn("GIT-READ-001", result["results"][0]["rule_ids"])
        finally:
            service.close()

    def test_policy_publish_rolls_back_when_audit_commit_fails(self) -> None:
        service = GuardService(self.settings)
        original_text = self.policy_path.read_text(encoding="utf-8")
        original_digest = service.policy.digest
        candidate = copy.deepcopy(service.policy.document)
        candidate["budgets"]["same_action_per_minute"] = 2
        candidate_text = yaml.safe_dump(candidate, sort_keys=False)
        try:
            with patch.object(service.store, "record_operator_action", side_effect=RuntimeError("audit unavailable")):
                with self.assertRaises(RuntimeError):
                    service.publish_policy(candidate_text, original_digest, "test")
            self.assertEqual(self.policy_path.read_text(encoding="utf-8"), original_text)
            self.assertEqual(service.policy.digest, original_digest)
        finally:
            service.close()

    def test_policy_publish_reconfigures_correlation_budgets(self) -> None:
        service = GuardService(self.settings)
        candidate = copy.deepcopy(service.policy.document)
        candidate["budgets"]["same_action_per_minute"] = 1
        candidate_text = yaml.safe_dump(candidate, sort_keys=False)
        try:
            service.publish_policy(candidate_text, service.policy.digest, "test")
            first = GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="budget-ui", tool=ToolDescriptor(name="health"))
            second = GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="budget-ui", tool=ToolDescriptor(name="health"))
            self.assertEqual(service.decide(first).decision.value, "ALLOW")
            decision = service.decide(second)
            self.assertEqual(decision.decision.value, "DENY")
            self.assertIn("LOOP-REPEAT-001", decision.rule_ids)
        finally:
            service.close()

    def test_retention_purges_old_events_and_preserves_recent_events(self) -> None:
        service = GuardService(self.settings)
        old = GuardEvent(
            event_type="tool.before", occurred_at=datetime.now(timezone.utc) - timedelta(days=40),
            source="test", agent_id="main", session_key="old", tool=ToolDescriptor(name="health"),
        )
        recent = GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key="recent", tool=ToolDescriptor(name="health"))
        try:
            service.decide(old)
            service.decide(recent)
            result = service.store.purge_before((datetime.now(timezone.utc) - timedelta(days=30)).isoformat())
            self.assertEqual(result["events"], 1)
            self.assertIsNone(service.store.get_event_detail(str(old.event_id)))
            self.assertIsNotNone(service.store.get_event_detail(str(recent.event_id)))
        finally:
            service.close()

    def test_existing_database_gets_pre_ui_migration_backup(self) -> None:
        first = GuardService(self.settings)
        first.close()
        backup = self.settings.db_path.with_name(f"{self.settings.db_path.name}.pre-ui-v1.bak")
        self.assertFalse(backup.exists())
        second = GuardService(self.settings)
        try:
            self.assertTrue(backup.is_file())
            self.assertGreater(backup.stat().st_size, 0)
        finally:
            second.close()


class UiPrimitiveTests(unittest.TestCase):
    def test_doctor_caps_each_command_and_returns_duration(self) -> None:
        completed = subprocess.CompletedProcess(["openclaw"], 0, stdout="ok", stderr="")
        with patch("guardd.doctor.subprocess.run", return_value=completed) as run:
            check = doctor_module._run("test", ["openclaw"], timeout_seconds=99)
        self.assertEqual(run.call_args.kwargs["timeout"], 20.0)
        self.assertEqual(check.status, "pass")
        self.assertGreaterEqual(check.duration_ms, 0)

    def test_ui_session_idle_expiry_and_logout(self) -> None:
        auth = UiAuthManager(idle_minutes=1, absolute_hours=1)
        now = datetime.now(timezone.utc)
        with patch.object(auth, "_now", return_value=now):
            code, _ = auth.create_bootstrap()
            raw, session = auth.consume_bootstrap(code)
            self.assertEqual(auth.validate(raw).operator, session.operator)
        with patch.object(auth, "_now", return_value=now + timedelta(minutes=2)):
            with self.assertRaises(UiAuthError):
                auth.validate(raw)
        with patch.object(auth, "_now", return_value=now):
            code, _ = auth.create_bootstrap()
            raw, _ = auth.consume_bootstrap(code)
            auth.destroy(raw)
            with self.assertRaises(UiAuthError):
                auth.validate(raw)

    def test_sse_event_bus_replays_only_newer_events(self) -> None:
        bus = EventBus(max_events=2)
        first = bus.publish("event.recorded", {"value": 1})
        second = bus.publish("decision.recorded", {"value": 2})
        third = bus.publish("approval.created", {"value": 3})
        self.assertEqual([item.event_id for item in bus.after(first.event_id)], [second.event_id, third.event_id])
        self.assertIn("event: approval.created", third.encode())
        self.assertIn(f"id: {third.event_id}", third.encode())


if __name__ == "__main__":
    unittest.main()
