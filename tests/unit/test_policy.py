from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from guardd.models.events import GuardEvent
from guardd.policy import PolicyEngine, PolicyLoader, PolicyValidationError


ROOT = Path(__file__).parents[2]


class PolicyFixtureTests(unittest.TestCase):
    def test_default_schema_is_a_packaged_guardd_resource(self) -> None:
        loader = PolicyLoader()
        self.assertEqual(loader.schema_path.parent.name, "policy")
        self.assertEqual(loader.schema_path.name, "policy.schema.json")
        self.assertTrue(loader.schema_path.is_file())

    def test_every_declared_fixture(self) -> None:
        fixture_paths = sorted((ROOT / "fixtures").glob("*/*.json"))
        self.assertGreaterEqual(len(fixture_paths), 30)
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            engine = PolicyEngine(PolicyLoader().load(ROOT / "policies/default.yaml"), workspace, resolve_dns=False)
            for path in fixture_paths:
                with self.subTest(fixture=str(path.relative_to(ROOT))):
                    fixture = json.loads(path.read_text(encoding="utf-8"))
                    decision = engine.decide(GuardEvent.model_validate(fixture["event"]))
                    proposed = decision.would_decide or decision.decision
                    self.assertEqual(proposed.value, fixture["expected"]["decision"])
                    self.assertEqual(decision.risk, fixture["expected"]["risk"])
                    self.assertTrue(set(fixture["expected"]["rule_ids"]) <= set(decision.rule_ids))
                    self.assertIn("parameter_digest", fixture["allowed_log_fields"])

    def test_policy_requires_unique_rule_ids(self) -> None:
        loader = PolicyLoader()
        policy = loader.load(ROOT / "policies/default.yaml")
        invalid = copy.deepcopy(policy.document)
        invalid["rules"].append(copy.deepcopy(invalid["rules"][0]))
        with self.assertRaises(PolicyValidationError):
            loader.parse(json.dumps(invalid))

    def test_deny_beats_allow_even_at_lower_priority(self) -> None:
        loader = PolicyLoader()
        document = copy.deepcopy(loader.load(ROOT / "policies/default.yaml").document)
        document["defaults"]["mode"] = "enforce"
        document["rules"].extend([
            {"id": "TEST-ALLOW-001", "priority": 9999, "match": {"tool": "test_conflict"}, "decision": "allow", "risk": "low", "reason": "allow"},
            {"id": "TEST-DENY-001", "priority": 1, "match": {"tool": "test_conflict"}, "decision": "deny", "risk": "high", "reason": "deny"},
        ])
        policy = loader.parse(json.dumps(document))
        event = GuardEvent.model_validate({"event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "s", "tool": {"name": "test_conflict"}})
        self.assertEqual(PolicyEngine(policy, Path.cwd()).decide(event).decision.value, "DENY")

    def test_observe_preserves_would_decide_without_guardd_blocking(self) -> None:
        engine = PolicyEngine(PolicyLoader().load(ROOT / "policies/default.yaml"), Path.cwd())
        git = GuardEvent.model_validate({"event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "s", "tool": {"name": "exec"}, "params": {"command": "git push origin main"}})
        root_delete = GuardEvent.model_validate({"event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "s2", "tool": {"name": "exec"}, "params": {"command": "rm -rf /"}})
        git_decision = engine.decide(git)
        self.assertEqual(git_decision.decision.value, "OBSERVE")
        self.assertEqual(git_decision.would_decide.value, "REQUIRE_APPROVAL")
        root_decision = engine.decide(root_delete)
        self.assertEqual(root_decision.decision.value, "OBSERVE")
        self.assertEqual(root_decision.would_decide.value, "DENY")

    def test_session_channel_sender_and_time_match_fields_are_supported(self) -> None:
        loader = PolicyLoader()
        document = copy.deepcopy(loader.load(ROOT / "policies/default.yaml").document)
        document["defaults"]["mode"] = "enforce"
        document["rules"].append({
            "id": "CONTEXT-MATCH-001", "priority": 2000,
            "match": {"session": "session-*", "channel": "telegram", "sender": "sender-1", "time_window": {"start": "00:00", "end": "23:59"}},
            "decision": "deny", "risk": "high", "reason": "context matched",
        })
        policy = loader.parse(json.dumps(document))
        event = GuardEvent.model_validate({
            "event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "session-42",
            "origin": {"channel": "telegram", "sender_id": "sender-1"}, "tool": {"name": "health"},
        })
        self.assertIn("CONTEXT-MATCH-001", PolicyEngine(policy, Path.cwd()).decide(event).rule_ids)

    def test_parameter_rewrite_is_included_before_digest_binding(self) -> None:
        loader = PolicyLoader()
        document = copy.deepcopy(loader.load(ROOT / "policies/default.yaml").document)
        document["defaults"]["mode"] = "enforce"
        document["rules"].append({
            "id": "REWRITE-TEST-001", "priority": 2100, "match": {"tool": "rewrite_test"},
            "decision": "allow", "risk": "low", "reason": "narrow target", "rewrite": {"target": "safe"},
        })
        engine = PolicyEngine(loader.parse(json.dumps(document)), Path.cwd(), resolve_dns=False)
        original = GuardEvent.model_validate({"event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "rewrite", "tool": {"name": "rewrite_test"}, "params": {"target": "broad"}})
        already_rewritten = GuardEvent.model_validate({"event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "rewrite", "tool": {"name": "rewrite_test"}, "params": {"target": "safe"}})
        first = engine.decide(original)
        second = engine.decide(already_rewritten)
        self.assertEqual(first.rewritten_params, {"target": "safe"})
        self.assertEqual(first.parameter_digest, second.parameter_digest)


if __name__ == "__main__":
    unittest.main()
