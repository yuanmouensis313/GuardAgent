from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from guardd.api.app import create_app
from guardd.config import Settings
from guardd.security import ensure_token


ROOT = Path(__file__).parents[2]


class TaskPolicyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        workspace = self.root / "workspace"
        workspace.mkdir()
        self.settings = Settings(
            state_dir=self.root / "state",
            policy_path=ROOT / "policies" / "default.yaml",
            workspace=workspace,
            ui_enabled=False,
            task_policy_mode="approval",
        )
        token = ensure_token(self.settings.token_path)
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.auth = {"Authorization": f"Bearer {token}"}

    def tearDown(self) -> None:
        self.client.close()
        self.app.state.service.close()
        self.temp.cleanup()

    def test_capture_get_activate_and_close(self) -> None:
        captured = self.client.post(
            "/v1/task-policies/capture", headers=self.auth,
            json={
                "schema_version": "1.0", "request_id": "capture-1",
                "session_key": "api-task", "agent_id": "main",
                "prompt": "读取 docs/input.md 并保存到 docs/output.md",
            },
        )
        self.assertEqual(captured.status_code, 200, captured.text)
        candidate = captured.json()
        self.assertEqual(candidate["status"], "candidate")

        fetched = self.client.get(
            "/v1/task-policies/api-task", headers=self.auth, params={"policy_status": "candidate"},
        )
        self.assertEqual(fetched.status_code, 200, fetched.text)
        self.assertEqual(fetched.json()["policy_digest"], candidate["policy_digest"])

        activated = self.client.post(
            "/v1/task-policies/api-task/activate", headers=self.auth,
            json={
                "schema_version": "1.0", "request_id": "activate-1",
                "candidate_digest": candidate["policy_digest"],
                "expected_active_revision": None, "operator": "tester",
            },
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["status"], "active")

        closed = self.client.post(
            "/v1/task-policies/api-task/close", headers=self.auth,
            json={"schema_version": "1.0", "request_id": "close-1", "operator": "tester"},
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["closed"], 1)

    def test_activation_rejects_wrong_digest(self) -> None:
        response = self.client.post(
            "/v1/task-policies/missing/activate", headers=self.auth,
            json={
                "schema_version": "1.0", "request_id": "activate-bad",
                "candidate_digest": "sha256:wrong", "operator": "tester",
            },
        )
        self.assertEqual(response.status_code, 409)


if __name__ == "__main__":
    unittest.main()
