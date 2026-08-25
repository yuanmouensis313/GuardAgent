from __future__ import annotations

from guardd.llm.models import ReviewTrigger
from guardd.models.decisions import Decision, DecisionKind


class ReviewTriggerPolicy:
    _REQUIRED_PREFIXES = (
        "PROMPT-INJECTION-",
        "DYNAMIC-EVAL-",
        "ENCODED-COMMAND-",
        "SECRET-EXFIL-",
        "CORRELATION-EXFIL-",
        "DENIAL-EVASION-",
        "TASK-POLICY-OUT-OF-SCOPE-",
        "CONTENT-INSPECTION-",
    )

    def __init__(self, sample_allow_rate: float = 0.01):
        self.sample_allow_rate = min(1.0, max(0.0, sample_allow_rate))

    def evaluate(self, decision: Decision, sample_key: str) -> ReviewTrigger:
        proposed = decision.would_decide or decision.decision
        if proposed == DecisionKind.DENY:
            return ReviewTrigger.SKIP
        if any(rule_id.startswith(self._REQUIRED_PREFIXES) for rule_id in decision.rule_ids):
            return ReviewTrigger.REVIEW_REQUIRED
        if decision.risk in {"high", "critical"}:
            return ReviewTrigger.REVIEW_REQUIRED
        if proposed == DecisionKind.REQUIRE_APPROVAL:
            return ReviewTrigger.REVIEW_OPTIONAL
        if self.sample_allow_rate and self._sample(sample_key) < self.sample_allow_rate:
            return ReviewTrigger.SAMPLE_SHADOW
        return ReviewTrigger.SKIP

    @staticmethod
    def _sample(value: str) -> float:
        try:
            suffix = value.removeprefix("sha256:")[-8:]
            return int(suffix, 16) / 0xFFFFFFFF
        except ValueError:
            return 1.0
