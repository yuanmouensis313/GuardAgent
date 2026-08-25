from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from guardd.llm.models import (
    IntentAlignment,
    ReviewVerdict,
    SafetyReviewInput,
    SafetyReviewResult,
    ValidationOutcome,
)
from guardd.security import sanitize


_PATH_TOKEN_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]")


class SafetyReviewValidator:
    def __init__(self, secret_patterns: list[tuple[str, re.Pattern[str]]] | None = None):
        self.secret_patterns = secret_patterns or []

    def validate(
        self,
        payload: dict[str, Any],
        input_document: SafetyReviewInput | dict[str, Any],
    ) -> ValidationOutcome:
        clean_payload, classifications = sanitize(payload, extra_patterns=self.secret_patterns)
        output_secret_echo = bool(classifications)
        issues: list[str] = []
        try:
            result = SafetyReviewResult.model_validate(clean_payload)
        except ValidationError:
            return ValidationOutcome(
                result=self._uncertain("Model output failed schema validation"),
                valid=False,
                issues=["LLM_OUTPUT_SCHEMA_INVALID"],
                output_secret_echo=output_secret_echo,
            )
        input_payload = (
            input_document.model_dump(mode="json")
            if isinstance(input_document, SafetyReviewInput)
            else input_document
        )
        invalid_evidence = [
            item.path for item in result.evidence
            if not self._path_exists(input_payload, item.path)
        ]
        if invalid_evidence:
            issues.append("LLM_OUTPUT_EVIDENCE_INVALID")
        if result.verdict == ReviewVerdict.DENY and not result.evidence:
            issues.append("LLM_OUTPUT_DENY_WITHOUT_EVIDENCE")
        if result.recommended_action == ReviewVerdict.ALLOW and result.verdict != ReviewVerdict.ALLOW:
            issues.append("LLM_OUTPUT_ACTION_CONTRADICTION")
        if output_secret_echo:
            issues.append("LLM_OUTPUT_SECRET_ECHO")
        if issues:
            return ValidationOutcome(
                result=self._uncertain("Model result was downgraded because validation evidence was insufficient"),
                valid=False,
                issues=issues,
                output_secret_echo=output_secret_echo,
            )
        return ValidationOutcome(
            result=result,
            valid=True,
            issues=[],
            output_secret_echo=False,
        )

    @staticmethod
    def _uncertain(summary: str) -> SafetyReviewResult:
        return SafetyReviewResult(
            verdict=ReviewVerdict.UNCERTAIN,
            risk="high",
            confidence=0.0,
            threats=[],
            intent_alignment=IntentAlignment.UNKNOWN,
            evidence=[],
            recommended_action=ReviewVerdict.REQUIRE_APPROVAL,
            constraints={},
            summary=summary,
        )

    @staticmethod
    def _path_exists(document: Any, path: str) -> bool:
        if path == "$":
            return True
        if not path.startswith("$"):
            return False
        current = document
        position = 1
        for match in _PATH_TOKEN_RE.finditer(path, position):
            if match.start() != position:
                return False
            key, index = match.groups()
            if key is not None:
                if not isinstance(current, dict) or key not in current:
                    return False
                current = current[key]
            else:
                parsed_index = int(index)
                if not isinstance(current, list) or parsed_index >= len(current):
                    return False
                current = current[parsed_index]
            position = match.end()
        return position == len(path)
