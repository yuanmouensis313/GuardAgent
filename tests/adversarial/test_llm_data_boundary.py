from __future__ import annotations

import copy
import json
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


class CapturingProvider:
    name = "capture"

    def __init__(self) -> None:
        self.requests = []

    def generate_structured(self, request, output_schema, timeout_ms):
        self.requests.append(request.model_dump(mode="json"))
        payload = {
            "schema_version": "1.0", "verdict": "REQUIRE_APPROVAL", "risk": "high",
            "confidence": 0.9, "threats": ["scope_escape"],
            "intent_alignment": "partially_aligned",
            "evidence": [{
                "source": "local_signals", "path": "$.local_signals.rule_ids[0]",
                "claim": "The local decision requires operator review",
            }],
            "recommended_action": "REQUIRE_APPROVAL", "constraints": {},
            "summary": "Keep the local approval requirement",
        }
        return ModelResponse(
            request_id=request.request_id, provider=self.name, model=request.model,
            payload=payload, raw_response_digest=digest_payload(payload), latency_ms=1,
        )


class LlmDataBoundaryTests(unittest.TestCase):
    def test_canary_never_reaches_provider_audit_database_or_public_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            policy = copy.deepcopy(PolicyLoader().load(ROOT / "policies/default.yaml").document)
            policy["defaults"]["mode"] = "enforce"
            policy_path = root / "policy.yaml"
            policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
            provider = CapturingProvider()
            service = GuardService(Settings(
                state_dir=root / "state", policy_path=policy_path, workspace=workspace,
                task_policy_enabled=False, llm_enabled=True, llm_model="capture-model",
                llm_base_url="http://127.0.0.1:11434/v1", llm_review_mode="shadow",
                llm_review_sample_allow_rate=0, llm_max_concurrency=1,
            ), llm_provider=provider)
            canary = "ghp_" + "CANARY0123456789abcdef" * 2
            try:
                event = GuardEvent.model_validate({
                    "event_type": "tool.before", "source": "test", "agent_id": "main",
                    "session_key": "canary-session", "tool": {"name": "exec", "kind": "shell"},
                    "params": {"command": "git push origin feature", "diagnostic_note": canary},
                })
                decision = service.decide(event)
                deadline = time.monotonic() + 3
                while not provider.requests and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(provider.requests)
                self.assertNotIn(canary, json.dumps(provider.requests, ensure_ascii=False))
                self.assertNotIn(canary, decision.model_dump_json())
                review = service.store.get_llm_review(str(decision.review_id))
                self.assertNotIn(canary, json.dumps(review, ensure_ascii=False, default=str))
            finally:
                service.close()
            self.assertNotIn(canary.encode(), (root / "state" / "guardagent.sqlite3").read_bytes())
            emergency = root / "state" / "emergency.jsonl"
            if emergency.exists():
                self.assertNotIn(canary, emergency.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
