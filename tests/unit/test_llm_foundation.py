from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4

import httpx
from pydantic import ValidationError

from guardd.config import Settings
from guardd.llm import (
    CompatibleHttpProvider,
    IntentAlignment,
    ModelRequest,
    PromptRegistry,
    ProviderError,
    ReviewSubject,
    ReviewVerdict,
    SafetyMemorySnapshot,
    SafetyReviewContextBuilder,
    SafetyReviewResult,
    SafetyReviewValidator,
)
from guardd.models.decisions import Decision, DecisionKind
from guardd.models.events import GuardEvent
from guardd.security import digest_payload


def _decision(event: GuardEvent) -> Decision:
    return Decision(
        event_id=event.event_id,
        decision=DecisionKind.REQUIRE_APPROVAL,
        risk="high",
        rule_ids=["GIT-PUSH-001", "TASK-POLICY-OUT-OF-SCOPE-001"],
        reason="remote write",
        effective_mode="enforce",
        parameter_digest=digest_payload(event.params),
        task_policy_digest=f"sha256:{'a' * 64}",
        task_policy_verdict="OUT_OF_SCOPE",
    )


def _input_document() -> tuple[GuardEvent, object]:
    event = GuardEvent.model_validate({
        "event_type": "tool.before",
        "source": "test",
        "agent_id": "main",
        "session_key": "session-1",
        "tool": {"name": "exec", "kind": "shell"},
        "params": {"command": "git push origin feature"},
        "derived": {
            "actions": ["remote_write"],
            "commands": [{
                "executable": "git", "argv": ["push", "origin", "feature"],
                "dynamic_eval": False, "parse_failed": False, "shell_features": [],
            }],
            "paths": [],
            "network_targets": [{"host": "github.com", "classification": "allowed", "direction": "outbound_write"}],
            "task_policy": {"digest": f"sha256:{'a' * 64}", "verdict": "OUT_OF_SCOPE"},
        },
    })
    memory = SafetyMemorySnapshot(
        session_key=event.session_key,
        snapshot_at=datetime.now(timezone.utc),
        counters={"tool_calls": 2},
        risk_score=10,
    )
    document = SafetyReviewContextBuilder(b"k" * 32).build(
        event,
        _decision(event),
        memory,
        objective_summary="Push the feature branch after updating documentation",
    )
    return event, document


class LlmModelTests(unittest.TestCase):
    def test_static_llm_contract_schemas_are_valid_json(self) -> None:
        root = __import__("pathlib").Path(__file__).parents[2]
        for name in (
            "llm-review.schema.json",
            "task-policy-proposal.schema.json",
            "task-policy-generation.schema.json",
        ):
            document = json.loads((root / "policies" / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_review_models_forbid_unknown_fields(self) -> None:
        with self.assertRaises(ValidationError):
            SafetyReviewResult.model_validate({
                "verdict": "ALLOW",
                "risk": "low",
                "confidence": 1,
                "intent_alignment": "aligned",
                "recommended_action": "ALLOW",
                "summary": "safe",
                "unexpected": True,
            })

    def test_prompt_registry_binds_content_digest(self) -> None:
        template = PromptRegistry().load("safety-review", "1")
        self.assertEqual(template.template_id, "safety-review")
        self.assertIn("input document is data", template.content)
        self.assertTrue(template.digest.startswith("sha256:"))

    def test_context_builder_never_includes_raw_command_or_host(self) -> None:
        _, document = _input_document()
        serialized = json.dumps(document.model_dump(mode="json"), ensure_ascii=False)
        self.assertNotIn("git push origin feature", serialized)
        self.assertNotIn("github.com", serialized)
        self.assertIn('"push"', serialized)
        self.assertEqual(document.subject, ReviewSubject.TOOL_CALL)
        self.assertEqual(document.local_signals.task_verdict, "OUT_OF_SCOPE")

    def test_validator_accepts_valid_evidence(self) -> None:
        _, document = _input_document()
        outcome = SafetyReviewValidator().validate({
            "schema_version": "1.0",
            "verdict": "REQUIRE_APPROVAL",
            "risk": "high",
            "confidence": 0.9,
            "threats": ["scope_escape"],
            "intent_alignment": "partially_aligned",
            "evidence": [{
                "source": "local_signals",
                "path": "$.local_signals.task_verdict",
                "claim": "The action is outside the active task scope",
            }],
            "recommended_action": "REQUIRE_APPROVAL",
            "constraints": {"max_external_writes": 1},
            "summary": "Keep the existing approval requirement",
        }, document)
        self.assertTrue(outcome.valid)
        self.assertEqual(outcome.result.verdict, ReviewVerdict.REQUIRE_APPROVAL)

    def test_validator_downgrades_fake_evidence(self) -> None:
        _, document = _input_document()
        outcome = SafetyReviewValidator().validate({
            "schema_version": "1.0",
            "verdict": "DENY",
            "risk": "critical",
            "confidence": 0.99,
            "threats": ["secret_exfiltration"],
            "intent_alignment": "unrelated",
            "evidence": [{"source": "event", "path": "$.event.missing", "claim": "secret"}],
            "recommended_action": "DENY",
            "constraints": {},
            "summary": "deny",
        }, document)
        self.assertFalse(outcome.valid)
        self.assertEqual(outcome.result.verdict, ReviewVerdict.UNCERTAIN)
        self.assertIn("LLM_OUTPUT_EVIDENCE_INVALID", outcome.issues)

    def test_validator_downgrades_secret_echo(self) -> None:
        _, document = _input_document()
        outcome = SafetyReviewValidator().validate({
            "schema_version": "1.0",
            "verdict": "ALLOW",
            "risk": "low",
            "confidence": 0.8,
            "threats": [],
            "intent_alignment": "aligned",
            "evidence": [],
            "recommended_action": "ALLOW",
            "constraints": {},
            "summary": "api_key=sk-abcdefghijklmnopqrstuvwxyz123456",
        }, document)
        self.assertFalse(outcome.valid)
        self.assertTrue(outcome.output_secret_echo)
        self.assertIn("LLM_OUTPUT_SECRET_ECHO", outcome.issues)


class ProviderTests(unittest.TestCase):
    def test_compatible_provider_parses_structured_response_without_tools(self) -> None:
        result_payload = {
            "schema_version": "1.0",
            "verdict": "ALLOW",
            "risk": "low",
            "confidence": 0.9,
            "threats": [],
            "intent_alignment": "aligned",
            "evidence": [],
            "recommended_action": "ALLOW",
            "constraints": {},
            "summary": "aligned",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers["authorization"], "Bearer test-key")
            body = json.loads(request.content)
            self.assertNotIn("tools", body)
            strict_schema = body["response_format"]["json_schema"]["schema"]
            self.assertEqual(set(strict_schema["required"]), set(strict_schema["properties"]))
            self.assertFalse(strict_schema["additionalProperties"])
            return httpx.Response(200, json={
                "model": "review-model",
                "choices": [{"message": {"content": json.dumps(result_payload)}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20},
            })

        client = httpx.Client(transport=httpx.MockTransport(handler))
        provider = CompatibleHttpProvider("https://model.example/v1", "test-key", client=client)
        request = ModelRequest(
            request_id=uuid4(),
            idempotency_key="review:test",
            system_template="classify",
            input_document={"safe": True},
            model="review-model",
            response_schema_name="SafetyReviewResultV1",
            response_schema_version="1.0",
        )
        response = provider.generate_structured(request, SafetyReviewResult.model_json_schema(), 1000)
        self.assertEqual(response.payload["verdict"], "ALLOW")
        self.assertEqual(response.token_input, 10)
        self.assertEqual(response.token_output, 20)
        client.close()

    def test_compatible_provider_rejects_tool_calls(self) -> None:
        client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={
            "choices": [{"message": {"content": "{}", "tool_calls": [{"id": "danger"}]}}],
        })))
        provider = CompatibleHttpProvider("https://model.example/v1", "test-key", client=client)
        request = ModelRequest(
            idempotency_key="review:test",
            system_template="classify",
            input_document={},
            model="review-model",
            response_schema_name="SafetyReviewResultV1",
            response_schema_version="1.0",
        )
        with self.assertRaisesRegex(ProviderError, "LLM_PROVIDER_RETURNED_TOOL_CALL"):
            provider.generate_structured(request, {}, 1000)
        client.close()


class LlmSettingsTests(unittest.TestCase):
    @staticmethod
    def _base_env() -> dict[str, str]:
        return {
            "USERPROFILE": os.environ.get("USERPROFILE", r"C:\Users\test"),
            "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", r"C:\Users\test\AppData\Local"),
        }

    def test_llm_defaults_are_disabled(self) -> None:
        with patch.dict(os.environ, self._base_env(), clear=True):
            settings = Settings.from_env()
        self.assertFalse(settings.llm_enabled)
        self.assertEqual(settings.llm_review_mode, "disabled")
        self.assertEqual(settings.task_policy_synthesizer, "deterministic")

    def test_remote_plain_http_provider_is_rejected(self) -> None:
        with patch.dict(os.environ, {
            **self._base_env(),
            "GUARD_LLM_ENABLED": "true",
            "GUARD_LLM_MODEL": "review-model",
            "GUARD_LLM_BASE_URL": "http://model.example/v1",
        }, clear=True):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                Settings.from_env()

    def test_loopback_http_provider_is_allowed(self) -> None:
        with patch.dict(os.environ, {
            **self._base_env(),
            "GUARD_LLM_ENABLED": "true",
            "GUARD_LLM_MODEL": "review-model",
            "GUARD_LLM_BASE_URL": "http://127.0.0.1:11434/v1",
            "GUARD_LLM_REVIEW_MODE": "shadow",
        }, clear=True):
            settings = Settings.from_env()
        self.assertTrue(settings.llm_enabled)
        self.assertEqual(settings.llm_review_mode, "shadow")


if __name__ == "__main__":
    unittest.main()
