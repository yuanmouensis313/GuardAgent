from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from guardd.config import Settings
from guardd.models.events import GuardEvent, Origin, ToolDescriptor
from guardd.service import GuardService
from guardd.task_policy import TaskPolicyError


ROOT = Path(__file__).parents[2]


class TaskPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        policy = yaml.safe_load((ROOT / "policies" / "default.yaml").read_text(encoding="utf-8"))
        policy["defaults"]["mode"] = "enforce"
        self.policy_path = self.state / "policy.yaml"
        self.policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        self.settings = Settings(
            state_dir=self.state,
            policy_path=self.policy_path,
            workspace=self.workspace,
            task_policy_mode="approval",
        )
        self.service = GuardService(self.settings)

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def capture(self, session: str = "task-session"):
        return self.service.capture_task_policy(
            "读取 https://example.com/posts 并把摘要保存到 reports/summary.md",
            session,
            "main",
        )

    def activate(self, candidate):
        return self.service.activate_task_policy(
            candidate.session_key, candidate.policy_digest, None, "tester",
        )

    def test_capture_extracts_minimal_tools_paths_and_domains(self) -> None:
        candidate = self.capture()
        expected_path = str((self.workspace / "reports" / "summary.md").resolve())

        self.assertEqual(candidate.status.value, "candidate")
        self.assertIn("web_fetch", candidate.tools.allow)
        self.assertIn("write", candidate.tools.allow)
        self.assertEqual(candidate.network.read, ["example.com"])
        self.assertEqual(candidate.files.write, [expected_path])
        self.assertNotIn(str(self.workspace / "https"), candidate.files.read + candidate.files.write)

    def test_candidate_matches_published_json_schema(self) -> None:
        candidate = self.capture("schema-task")
        schema = json.loads((ROOT / "policies" / "schemas" / "task-policy.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(candidate.model_dump(mode="json"))

    def test_raw_secret_is_not_persisted_in_task_policy(self) -> None:
        secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456"
        candidate = self.service.capture_task_policy(
            f"读取 reports/input.md，使用 token={secret}，保存到 reports/output.md",
            "secret-task", "main",
        )
        with self.service.store._lock:
            row = self.service.store._connection.execute(
                "SELECT objective_json, policy_json FROM task_policies WHERE task_policy_id=?",
                (str(candidate.task_policy_id),),
            ).fetchone()
        self.assertNotIn(secret, row["objective_json"])
        self.assertNotIn(secret, row["policy_json"])
        self.assertTrue(candidate.objective.source_digest.startswith("hmac-sha256:"))

    def test_activation_is_digest_and_revision_bound(self) -> None:
        candidate = self.capture()
        active = self.activate(candidate)
        self.assertEqual(active.status.value, "active")
        self.assertEqual(active.policy_digest, candidate.policy_digest)
        with self.assertRaises(TaskPolicyError):
            self.service.activate_task_policy(candidate.session_key, candidate.policy_digest, None, "tester")

    def test_pending_candidate_blocks_before_single_use_approval(self) -> None:
        candidate = self.capture("pending-task")
        event = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=candidate.session_key,
            tool=ToolDescriptor(name="write"), params={"path": "reports/summary.md", "content": "ok"},
        )

        decision = self.service.decide(event)

        self.assertEqual(decision.decision.value, "REQUIRE_APPROVAL")
        self.assertIn("TASK-POLICY-PENDING-001", decision.rule_ids)
        self.assertEqual(decision.task_policy_digest, candidate.policy_digest)
        self.assertEqual(decision.task_policy_revision, candidate.revision)
        self.assertEqual(decision.task_policy_verdict, "PENDING_CONFIRMATION")

    def test_permission_expansion_creates_revision_candidate_and_pauses_old_scope(self) -> None:
        first = self.service.capture_task_policy("保存到 reports/one.md", "revision-expand", "main")
        active = self.activate(first)
        expanded = self.service.capture_task_policy(
            "保存到 reports/one.md 和 reports/two.md", "revision-expand", "main",
        )
        self.assertEqual(expanded.status.value, "revision_candidate")
        self.assertEqual(expanded.revision, active.revision + 1)

        old_scope_call = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=active.session_key,
            tool=ToolDescriptor(name="write"), params={"path": "reports/one.md", "content": "ok"},
        )
        decision = self.service.decide(old_scope_call)
        self.assertIn("TASK-POLICY-PENDING-001", decision.rule_ids)
        self.assertEqual(decision.task_policy_revision, expanded.revision)

    def test_pure_narrowing_auto_activates_new_revision(self) -> None:
        first = self.service.capture_task_policy(
            "保存到 reports/one.md 和 reports/two.md", "revision-narrow", "main",
        )
        active = self.activate(first)
        narrowed = self.service.capture_task_policy("保存到 reports/one.md", "revision-narrow", "main")

        self.assertEqual(narrowed.status.value, "active")
        self.assertEqual(narrowed.revision, active.revision + 1)
        self.assertEqual(narrowed.files.write, [str((self.workspace / "reports" / "one.md").resolve())])
        self.assertLessEqual(narrowed.limits.expires_at, active.limits.expires_at)
        self.assertIsNone(self.service.task_policies.store.get_pending_task_policy("revision-narrow"))

    def test_tool_call_limit_is_enforced_from_durable_usage(self) -> None:
        candidate = self.service.capture_task_policy(
            "最多调用 1 次工具，保存到 reports/once.md", "limit-task", "main",
        )
        active = self.activate(candidate)
        first = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=active.session_key,
            tool=ToolDescriptor(name="write"), params={"path": "reports/once.md", "content": "first"},
        )
        second = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=active.session_key,
            tool=ToolDescriptor(name="write"), params={"path": "reports/once.md", "content": "second"},
        )

        self.assertEqual(self.service.decide(first).decision.value, "ALLOW")
        decision = self.service.decide(second)
        self.assertEqual(decision.decision.value, "REQUIRE_APPROVAL")
        self.assertIn("tool-call limit 1", decision.reason)

    def test_child_policy_is_intersection_and_parent_close_invalidates_child(self) -> None:
        parent_candidate = self.service.capture_task_policy(
            "读取 reports/input.md 并保存到 reports/parent.md", "parent-task", "parent-agent",
        )
        parent = self.activate(parent_candidate)
        child_candidate = self.service.capture_task_policy(
            "保存到 reports/parent.md 和 reports/outside.md", "child-task", "child-agent", "parent-task",
        )
        self.assertEqual(child_candidate.parent_policy_digest, parent.policy_digest)
        self.assertEqual(child_candidate.files.write, [str((self.workspace / "reports" / "parent.md").resolve())])
        child = self.service.activate_task_policy(
            "child-task", child_candidate.policy_digest, None, "tester",
        )
        allowed = GuardEvent(
            event_type="tool.before", source="test", agent_id="child-agent", session_key="child-task",
            parent_session_key="parent-task", tool=ToolDescriptor(name="write"),
            params={"path": "reports/parent.md", "content": "ok"},
        )
        self.assertEqual(self.service.decide(allowed).decision.value, "ALLOW")

        self.service.close_task_policy("parent-task", "tester")
        self.assertEqual(self.service.get_task_policy(child.session_key).status.value, "closed")

    def test_child_without_own_policy_gets_parent_read_only_subset(self) -> None:
        parent = self.activate(self.service.capture_task_policy(
            "读取 reports/input.md 并保存到 reports/output.md", "readonly-parent", "parent",
        ))
        read_event = GuardEvent(
            event_type="tool.before", source="test", agent_id="child", session_key="readonly-child",
            parent_session_key=parent.session_key, tool=ToolDescriptor(name="read"),
            params={"path": "reports/input.md"},
        )
        write_event = GuardEvent(
            event_type="tool.before", source="test", agent_id="child", session_key="readonly-child",
            parent_session_key=parent.session_key, tool=ToolDescriptor(name="write"),
            params={"path": "reports/output.md", "content": "no"},
        )
        self.assertEqual(self.service.decide(read_event).decision.value, "ALLOW")
        write_decision = self.service.decide(write_event)
        self.assertEqual(write_decision.decision.value, "REQUIRE_APPROVAL")
        self.assertEqual(write_decision.task_policy_verdict, "OUT_OF_SCOPE")

    def test_agent_and_sender_binding_prevents_session_key_reuse(self) -> None:
        candidate = self.service.capture_task_policy(
            "读取 docs/input.md", "bound-session", "main", None,
            Origin(channel="chat", sender_id="alice"),
        )
        active = self.activate(candidate)
        event = GuardEvent(
            event_type="tool.before", source="test", agent_id="other-agent", session_key=active.session_key,
            origin=Origin(channel="chat", sender_id="mallory"),
            tool=ToolDescriptor(name="read"), params={"path": "docs/input.md"},
        )
        decision = self.service.decide(event)
        self.assertEqual(decision.decision.value, "REQUIRE_APPROVAL")
        self.assertIn("agent other-agent", decision.reason)
        self.assertIn("sender", decision.reason)

    def test_in_scope_write_allowed_and_out_of_scope_write_requires_approval(self) -> None:
        active = self.activate(self.capture())
        allowed = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=active.session_key,
            tool=ToolDescriptor(name="write"), params={"path": "reports/summary.md", "content": "ok"},
        )
        outside = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=active.session_key,
            tool=ToolDescriptor(name="write"), params={"path": "README.md", "content": "injected"},
        )

        allowed_decision = self.service.decide(allowed)
        outside_decision = self.service.decide(outside)

        self.assertEqual(allowed_decision.decision.value, "ALLOW")
        self.assertEqual(allowed_decision.task_policy_verdict, "ALLOW")
        self.assertEqual(outside_decision.decision.value, "REQUIRE_APPROVAL")
        self.assertIn("TASK-POLICY-OUT-OF-SCOPE-001", outside_decision.rule_ids)

    def test_base_deny_wins_over_task_scope(self) -> None:
        candidate = self.service.capture_task_policy(
            "执行 shell 命令并删除 /", "base-wins", "main",
        )
        active = self.activate(self.service.get_task_policy("base-wins", "candidate"))
        event = GuardEvent(
            event_type="tool.before", source="test", agent_id="main", session_key=active.session_key,
            tool=ToolDescriptor(name="exec", kind="shell", input_kind="bash"),
            params={"command": "rm -rf /"},
        )
        decision = self.service.decide(event)
        self.assertEqual(decision.decision.value, "DENY")
        self.assertIn("ROOT-DELETE-001", decision.rule_ids)

    def test_session_end_closes_active_policy(self) -> None:
        active = self.activate(self.capture("closing"))
        self.service.session_event(GuardEvent(
            event_type="session.end", source="test", agent_id="main", session_key=active.session_key,
        ))
        closed = self.service.get_task_policy(active.session_key)
        self.assertEqual(closed.status.value, "closed")


if __name__ == "__main__":
    unittest.main()
