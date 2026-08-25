from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from guardd.api import create_app
from guardd.config import Settings
from guardd.policy import PolicyLoader
from guardd.security import ensure_token
from uuid import uuid4


ROOT = Path(__file__).parents[2]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        workspace = root / "workspace"
        workspace.mkdir()
        policy = copy.deepcopy(PolicyLoader().load(ROOT / "policies/default.yaml").document)
        policy["defaults"]["mode"] = "enforce"
        policy_path = root / "policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        self.settings = Settings(state_dir=root / "state", policy_path=policy_path, workspace=workspace)
        self.token = ensure_token(self.settings.token_path)
        self.client_context = TestClient(create_app(self.settings))
        self.client = self.client_context.__enter__()
        self.auth = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        self.temp.cleanup()

    def request(self, command: str) -> dict:
        return {
            "schema_version": "1.0", "request_id": "req-1",
            "event": {
                "event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": "api",
                "tool": {"name": "exec", "kind": "shell", "input_kind": "bash"},
                "params": {"command": command},
            },
        }

    def test_health_and_authentication(self) -> None:
        self.assertEqual(self.client.get("/v1/health").status_code, 200)
        self.assertEqual(self.client.get("/v1/status").status_code, 401)
        status = self.client.get("/v1/status", headers=self.auth)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["database_integrity"], "ok")

        capabilities = self.client.get("/v1/capabilities", headers=self.auth).json()
        inspection = capabilities["content_inspection"]
        self.assertFalse(inspection["skill_authoritative_use_identity"])
        self.assertEqual(inspection["mcp_proxy_transports"], ["stdio"])
        self.assertEqual(inspection["mcp_unprotected_transports"], ["sse", "streamable_http"])
        self.assertFalse(capabilities["llm_review"]["enabled"])
        self.assertFalse(capabilities["llm_review"]["can_loosen_base_policy"])
        self.assertTrue(capabilities["task_policy"]["deterministic_fallback"])
        self.assertFalse(self.client.get("/v1/llm/health", headers=self.auth).json()["enabled"])

    def test_decision_and_approval_endpoints(self) -> None:
        response = self.client.post("/v1/decisions/tool", headers=self.auth, json=self.request("git push origin main"))
        self.assertEqual(response.status_code, 200)
        decision = response.json()
        self.assertEqual(decision["decision"], "REQUIRE_APPROVAL")
        pending = self.client.get("/v1/approvals", headers=self.auth).json()
        self.assertEqual(len(pending), 1)
        resolution = self.client.post(
            f"/v1/approvals/{decision['approval_id']}/allow-once", headers=self.auth,
            json={"schema_version": "1.0", "request_id": "resolve", "operator": "test"},
        )
        self.assertEqual(resolution.status_code, 200)
        self.assertEqual(resolution.json()["status"], "allowed_once")
        explicit_review = self.client.post(
            f"/v1/events/{decision['event_id']}/review", headers=self.auth,
            json={"schema_version": "1.0", "request_id": "review", "operator": "test"},
        )
        self.assertEqual(explicit_review.status_code, 409)

    def test_strict_content_type_and_schema(self) -> None:
        response = self.client.post("/v1/decisions/tool", headers=self.auth, content="{}")
        self.assertEqual(response.status_code, 415)
        invalid = self.client.post("/v1/decisions/tool", headers=self.auth, json={"schema_version": "2.0"})
        self.assertEqual(invalid.status_code, 422)
        oversized = self.client.post(
            "/v1/decisions/tool", headers={**self.auth, "Content-Type": "application/json"},
            content=b" " * (self.settings.request_limit_bytes + 1),
        )
        self.assertEqual(oversized.status_code, 413)

    def test_security_override_requires_independent_credential(self) -> None:
        response = self.client.post(
            f"/v1/approvals/{uuid4()}/override-review-block",
            headers=self.auth,
            json={
                "schema_version": "1.0", "request_id": "override-auth", "operator": "test",
                "parameter_digest": f"sha256:{'a' * 64}",
                "reason": "Testing independent credential enforcement",
                "confirmation": "OVERRIDE_LLM_DENY",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_policy_validate_and_simulate(self) -> None:
        policy_text = self.settings.policy_path.read_text(encoding="utf-8")
        validation = self.client.post("/v1/policy/validate", headers=self.auth, json={"schema_version": "1.0", "request_id": "v", "policy": policy_text})
        self.assertTrue(validation.json()["valid"])
        simulation = self.client.post("/v1/policy/simulate", headers=self.auth, json=self.request("rm -rf /"))
        self.assertEqual(simulation.json()["decision"], "DENY")

    def test_secret_bearing_external_write_returns_block_transformation(self) -> None:
        body = self.request("ignored")
        body["event"]["tool"] = {"name": "message_send", "kind": "tool"}
        body["event"]["params"] = {
            "to": "https://example.com/inbox",
            "content": "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456",
        }
        response = self.client.post("/v1/decisions/message", headers=self.auth, json=body)
        self.assertEqual(response.status_code, 200)
        decision = response.json()
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("SECRET-EXFIL-001", decision["rule_ids"])
        self.assertEqual({item["action"] for item in decision["transformation_plan"]}, {"block"})
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", response.text)

    def test_sanitization_event_persists_metadata_only(self) -> None:
        response = self.client.post(
            "/v1/events/sanitization", headers=self.auth,
            json={
                "schema_version": "1.0", "request_id": "san-1", "sanitizer_event_id": "san-1",
                "direction": "inbound", "session_key": "sha256:session", "tool_name": "web_fetch",
                "classifications": ["github_token"],
                "transformations": [{
                    "json_path": "$.content", "classification": "github_token", "length": 40,
                    "source": "value-pattern", "proposed_action": "redact", "ref": "event-local-1",
                }],
                "original_size": 100, "result_size": 80, "truncated": False, "blocked": False,
            },
        )
        self.assertEqual(response.status_code, 202)
        rows = self.client.app.state.service.store.list_sanitization_events("sha256:session")
        self.assertEqual(rows[0]["classifications"], ["github_token"])
        self.assertEqual(rows[0]["transformations"][0]["json_path"], "$.content")
        self.assertEqual(self.client.app.state.service.store.sanitization_metrics()["total"], 1)


if __name__ == "__main__":
    unittest.main()
