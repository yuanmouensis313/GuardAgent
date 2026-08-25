from __future__ import annotations

import unittest
from uuid import uuid4

from guardd.llm import (
    DecisionFusionEngine,
    ReviewMode,
    ReviewTrigger,
    SafetyReviewResult,
)
from guardd.models.decisions import Decision, DecisionKind


def base_decision(kind: DecisionKind = DecisionKind.ALLOW) -> Decision:
    return Decision(
        event_id=uuid4(),
        decision=kind,
        risk="low",
        rule_ids=["TEST-BASE-001"],
        reason="base",
        effective_mode="enforce",
        parameter_digest="sha256:test",
    )


def review(verdict: str, *, confidence: float = 0.99, threats=None, evidence=True):
    return SafetyReviewResult.model_validate({
        "schema_version": "1.0",
        "verdict": verdict,
        "risk": "critical" if verdict == "DENY" else "high",
        "confidence": confidence,
        "threats": threats or [],
        "intent_alignment": "unrelated" if verdict == "DENY" else "unknown",
        "evidence": [{
            "source": "local_signals",
            "path": "$.local_signals.rule_ids",
            "claim": "evidence",
        }] if evidence else [],
        "recommended_action": verdict if verdict != "UNCERTAIN" else "REQUIRE_APPROVAL",
        "constraints": {},
        "summary": f"{verdict.lower()} review",
    })


class DecisionFusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fusion = DecisionFusionEngine()

    def test_deterministic_deny_is_never_relaxed(self) -> None:
        base = base_decision(DecisionKind.DENY)
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_REQUIRED,
            review("ALLOW", confidence=1),
            ReviewMode.ENFORCE_TIGHTEN,
        )
        self.assertEqual(result.decision, DecisionKind.DENY)
        self.assertEqual(result.rule_ids, ["TEST-BASE-001"])

    def test_model_allow_does_not_remove_existing_approval(self) -> None:
        base = base_decision(DecisionKind.REQUIRE_APPROVAL)
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_OPTIONAL,
            review("ALLOW"),
            ReviewMode.ENFORCE_TIGHTEN,
        )
        self.assertEqual(result.decision, DecisionKind.REQUIRE_APPROVAL)

    def test_high_confidence_enforceable_deny_tightens_allow(self) -> None:
        base = base_decision()
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_REQUIRED,
            review("DENY", threats=["prompt_injection"]),
            ReviewMode.ENFORCE_TIGHTEN,
        )
        self.assertEqual(result.decision, DecisionKind.DENY)
        self.assertIn("LLM-REVIEW-DENY-001", result.rule_ids)
        self.assertEqual(result.risk, "critical")

    def test_non_enforceable_deny_only_requires_approval(self) -> None:
        base = base_decision()
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_REQUIRED,
            review("DENY", threats=["unrelated_action"]),
            ReviewMode.ENFORCE_TIGHTEN,
        )
        self.assertEqual(result.decision, DecisionKind.REQUIRE_APPROVAL)

    def test_uncertain_required_review_tightens_allow_to_approval(self) -> None:
        base = base_decision()
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_REQUIRED,
            review("UNCERTAIN", confidence=0, evidence=False),
            ReviewMode.ENFORCE_TIGHTEN,
        )
        self.assertEqual(result.decision, DecisionKind.REQUIRE_APPROVAL)

    def test_shadow_never_changes_effective_decision(self) -> None:
        base = base_decision()
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_REQUIRED,
            review("DENY", threats=["prompt_injection"]),
            ReviewMode.SHADOW,
        )
        self.assertEqual(result.decision, DecisionKind.ALLOW)

    def test_observe_mode_updates_would_decide_only(self) -> None:
        base = base_decision(DecisionKind.OBSERVE)
        base.would_decide = DecisionKind.ALLOW
        result = self.fusion.fuse(
            base,
            ReviewTrigger.REVIEW_REQUIRED,
            review("DENY", threats=["security_bypass"]),
            ReviewMode.ENFORCE_TIGHTEN,
        )
        self.assertEqual(result.decision, DecisionKind.OBSERVE)
        self.assertEqual(result.would_decide, DecisionKind.DENY)


if __name__ == "__main__":
    unittest.main()
