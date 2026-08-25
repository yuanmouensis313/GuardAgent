from __future__ import annotations

from typing import Any

from guardd.llm.models import (
    ReviewMode,
    ReviewThreat,
    ReviewTrigger,
    ReviewVerdict,
    SafetyReviewResult,
)
from guardd.models.decisions import DECISION_ORDER, Decision, DecisionKind, RiskLevel


class DecisionFusionEngine:
    def __init__(
        self,
        *,
        deny_confidence_threshold: float = 0.92,
        approval_confidence_threshold: float = 0.65,
        enforceable_threats: set[str] | None = None,
    ):
        self.deny_confidence_threshold = min(1.0, max(0.0, deny_confidence_threshold))
        self.approval_confidence_threshold = min(1.0, max(0.0, approval_confidence_threshold))
        self.enforceable_threats = enforceable_threats or {
            ReviewThreat.PROMPT_INJECTION.value,
            ReviewThreat.SECRET_EXFILTRATION.value,
            ReviewThreat.SECURITY_BYPASS.value,
            ReviewThreat.DESTRUCTIVE_ACTION.value,
        }

    def fuse(
        self,
        base: Decision,
        trigger: ReviewTrigger,
        review: SafetyReviewResult | dict[str, Any],
        mode: ReviewMode,
    ) -> Decision:
        result = review if isinstance(review, SafetyReviewResult) else self._from_record(review)
        if (
            mode in {ReviewMode.DISABLED, ReviewMode.SHADOW, ReviewMode.ADVISORY}
            or trigger == ReviewTrigger.SAMPLE_SHADOW
        ):
            return base
        proposed = base.would_decide or base.decision
        if proposed == DecisionKind.DENY:
            return base
        target = proposed
        if result.verdict == ReviewVerdict.DENY:
            threats = {item.value for item in result.threats}
            enforceable = bool(threats & self.enforceable_threats)
            if (
                result.confidence >= self.deny_confidence_threshold
                and result.evidence
                and enforceable
            ):
                target = DecisionKind.DENY
            else:
                target = DecisionKind.REQUIRE_APPROVAL
        elif result.verdict == ReviewVerdict.REQUIRE_APPROVAL:
            if result.confidence >= self.approval_confidence_threshold:
                target = DecisionKind.REQUIRE_APPROVAL
        elif result.verdict == ReviewVerdict.UNCERTAIN and trigger == ReviewTrigger.REVIEW_REQUIRED:
            target = DecisionKind.REQUIRE_APPROVAL
        if DECISION_ORDER[target] <= DECISION_ORDER[proposed]:
            return base
        if base.decision == DecisionKind.OBSERVE:
            base.would_decide = target
        else:
            base.decision = target
        if target == DecisionKind.DENY:
            rule_id = "LLM-REVIEW-DENY-001"
        else:
            rule_id = "LLM-REVIEW-APPROVAL-001"
        if rule_id not in base.rule_ids:
            base.rule_ids.append(rule_id)
        base.risk = self._max_risk(base.risk, result.risk)
        base.reason = f"{base.reason}; semantic review: {result.summary[:500]}"
        if target == DecisionKind.REQUIRE_APPROVAL:
            base.remediation = "Review the semantic risk evidence and approve only the exact bound action"
        return base

    @staticmethod
    def _max_risk(left: str, right: str) -> str:
        left_level = RiskLevel[left] if left in RiskLevel.__members__ else RiskLevel.medium
        right_level = RiskLevel[right] if right in RiskLevel.__members__ else RiskLevel.medium
        return max(left_level, right_level).name

    @staticmethod
    def _from_record(record: dict[str, Any]) -> SafetyReviewResult:
        return SafetyReviewResult.model_validate({
            "schema_version": record.get("schema_version", "1.0"),
            "verdict": record["verdict"],
            "risk": record["risk"],
            "confidence": record["confidence"],
            "threats": record.get("threats", []),
            "intent_alignment": record.get("intent_alignment", "unknown"),
            "evidence": record.get("evidence", []),
            "recommended_action": record.get("recommended_action", record["verdict"]),
            "constraints": record.get("constraints", {}),
            "summary": record.get("sanitized_summary") or record.get("summary") or "Semantic review completed",
        })
