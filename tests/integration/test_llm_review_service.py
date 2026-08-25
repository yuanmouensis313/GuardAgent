from __future__ import annotations

import copy
import tempfile
import time
import unittest
from pathlib import Path

import yaml

from guardd.config import Settings
from guardd.llm import ModelResponse
from guardd.models.events import GuardEvent
from guardd.policy import PolicyLoader
from guardd.security import digest_payload
from guardd.service import GuardService


ROOT = Path(__file__).parents[2]


class ServiceFakeProvider:
    name = "fake"

    def __init__(self, verdict: str = "REQUIRE_APPROVAL"):
        self.verdict = verdict
        self.calls = 0

    def generate_structured(self, request, output_schema, timeout_ms):
        self.calls += 1
        deny = self.verdict == "DENY"
        payload = {
            "schema_version": "1.0",
            "verdict": self.verdict,
            "risk": "critical" if deny else "high",
            "confidence": 0.99,
            "threats": ["security_bypass"] if deny else ["scope_escape"],
            "intent_alignment": "unrelated" if deny else "partially_aligned",
            "evidence": [{
                "source": "local_signals",
                "path": "$.local_signals.rule_ids[0]",
                "claim": "The local policy requires review",
            }],
            "recommended_action": self.verdict,
            "constraints": {},
            "summary": "Deny the action" if deny else "Keep the approval requirement",
        }
        return ModelResponse(
            request_id=request.request_id,
            provider=self.name,
            model=request.model,
            payload=payload,
            raw_response_digest=digest_payload(payload),
            latency_ms=1,
        )


class LlmReviewServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        policy = copy.deepcopy(PolicyLoader().load(ROOT / "policies/default.yaml").document)
        policy["defaults"]["mode"] = "enforce"
        self.policy_path = self.root / "policy.yaml"
        self.policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        self.services: list[GuardService] = []

    def tearDown(self) -> None:
        for service in self.services:
            service.close()
        self.temp.cleanup()

    def service(self, provider, mode: str = "enforce_tighten") -> GuardService:
        instance = GuardService(Settings(
            state_dir=self.root / f"state-{len(self.services)}",
            policy_path=self.policy_path,
            workspace=self.workspace,
            task_policy_enabled=False,
            llm_enabled=True,
            llm_model="fake-review",
            llm_base_url="http://127.0.0.1:11434/v1",
            llm_review_mode=mode,
            llm_review_sample_allow_rate=0,
            llm_max_concurrency=1,
        ), llm_provider=provider)
        self.services.append(instance)
        return instance

    @staticmethod
    def event() -> GuardEvent:
        return GuardEvent.model_validate({
            "event_type": "tool.before",
            "source": "test",
            "agent_id": "main",
            "session_key": "llm-service",
            "tool": {"name": "exec", "kind": "shell"},
            "params": {"command": "git push origin feature"},
        })

    @staticmethod
    def wait_for_review(service: GuardService, review_id: str) -> dict:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            row = service.store.get_llm_review(review_id)
            if row and row["status"] == "completed":
                return row
            time.sleep(0.02)
        raise AssertionError("review did not complete")

    def test_required_review_blocks_first_attempt_then_uses_cache(self) -> None:
        provider = ServiceFakeProvider()
        service = self.service(provider)
        first = service.decide(self.event())
        self.assertEqual(first.decision.value, "REQUIRE_APPROVAL")
        self.assertIn("LLM-REVIEW-PENDING-001", first.rule_ids)
        self.assertIsNotNone(first.review_id)
        self.wait_for_review(service, str(first.review_id))

        second = service.decide(self.event())
        self.assertEqual(second.review_status, "completed")
        self.assertEqual(second.review_verdict, "REQUIRE_APPROVAL")
        self.assertNotIn("LLM-REVIEW-PENDING-001", second.rule_ids)
        self.assertEqual(second.decision.value, "REQUIRE_APPROVAL")
        self.assertEqual(provider.calls, 1)

    def test_cached_high_confidence_review_can_only_tighten_to_deny(self) -> None:
        provider = ServiceFakeProvider("DENY")
        service = self.service(provider)
        first = service.decide(self.event())
        self.wait_for_review(service, str(first.review_id))
        second = service.decide(self.event())
        self.assertEqual(second.decision.value, "DENY")
        self.assertIn("LLM-REVIEW-DENY-001", second.rule_ids)

    def test_shadow_review_never_changes_effective_decision(self) -> None:
        provider = ServiceFakeProvider("DENY")
        service = self.service(provider, mode="shadow")
        first = service.decide(self.event())
        self.assertEqual(first.decision.value, "REQUIRE_APPROVAL")
        self.assertNotIn("LLM-REVIEW-PENDING-001", first.rule_ids)
        self.wait_for_review(service, str(first.review_id))
        second = service.decide(self.event())
        self.assertEqual(second.decision.value, "REQUIRE_APPROVAL")
        self.assertNotIn("LLM-REVIEW-DENY-001", second.rule_ids)

    def test_high_confidence_deny_requires_explicit_digest_bound_override(self) -> None:
        provider = ServiceFakeProvider("DENY")
        service = self.service(provider)
        first = service.decide(self.event())
        self.wait_for_review(service, str(first.review_id))
        approval = service.approvals.list()[0]
        self.assertEqual(approval["resolution_gate"], "blocked_by_review")
        with self.assertRaisesRegex(ValueError, "blocked by semantic review"):
            service.resolve_approval(first.approval_id, True, "operator")
        with self.assertRaisesRegex(ValueError, "parameter digest mismatch"):
            service.override_review_block(
                first.approval_id,
                parameter_digest=f"sha256:{'0' * 64}",
                operator="security-operator",
                reason="Validated false positive after local reproduction",
                confirmation="OVERRIDE_LLM_DENY",
            )
        released = service.override_review_block(
            first.approval_id,
            parameter_digest=first.parameter_digest,
            operator="security-operator",
            reason="Validated false positive after local reproduction",
            confirmation="OVERRIDE_LLM_DENY",
        )
        self.assertEqual(released["status"], "review_overridden")
        retried = service.decide(self.event())
        self.assertEqual(retried.decision.value, "REQUIRE_APPROVAL")
        self.assertIn("LLM-REVIEW-OVERRIDE-APPROVAL-001", retried.rule_ids)
        self.assertNotIn("LLM-REVIEW-DENY-001", retried.rule_ids)
        allowed = service.resolve_approval(retried.approval_id, True, "security-operator")
        self.assertEqual(allowed["status"], "allowed_once")

    def test_operator_can_request_review_for_persisted_event(self) -> None:
        provider = ServiceFakeProvider()
        service = self.service(provider, mode="shadow")
        event = self.event()
        decision = service.decide(event)
        self.wait_for_review(service, str(decision.review_id))
        result = service.request_event_review(event.event_id, "security-operator")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["cache_hit"])


if __name__ == "__main__":
    unittest.main()
