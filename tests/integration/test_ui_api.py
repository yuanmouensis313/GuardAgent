from __future__ import annotations

import copy
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from guardd.api import create_app
from guardd.config import Settings
from guardd.policy import PolicyLoader
from guardd.security import ensure_token


ROOT = Path(__file__).parents[2]


class UiApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.root = root
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        policy = copy.deepcopy(PolicyLoader().load(ROOT / "policies/default.yaml").document)
        policy["defaults"]["mode"] = "enforce"
        self.policy_path = root / "policy.yaml"
        self.policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        self.settings = Settings(state_dir=root / "state", policy_path=self.policy_path, workspace=self.workspace)
        self.token = ensure_token(self.settings.token_path)
        self.context = TestClient(create_app(self.settings))
        self.client = self.context.__enter__()
        self.machine_auth = {"Authorization": f"Bearer {self.token}"}
        self.origin = f"http://127.0.0.1:{self.settings.port}"
        bootstrap = self.client.post(
            "/v1/ui/auth/bootstrap", headers=self.machine_auth,
            json={"schema_version": "1.0", "request_id": "bootstrap"},
        )
        self.assertEqual(bootstrap.status_code, 200)
        self.bootstrap_code = bootstrap.json()["code"]
        session = self.client.post(
            "/v1/ui/auth/session",
            headers={"Origin": self.origin},
            json={"schema_version": "1.0", "request_id": "session", "code": self.bootstrap_code},
        )
        self.assertEqual(session.status_code, 200)
        self.session_response = session
        self.csrf = session.json()["csrf_token"]
        self.write_headers = {"Origin": self.origin, "X-Guard-CSRF": self.csrf}

    def tearDown(self) -> None:
        self.context.__exit__(None, None, None)
        self.temp.cleanup()

    @staticmethod
    def event(command: str, session: str = "ui-session") -> dict:
        return {
            "schema_version": "1.0", "request_id": f"request-{session}",
            "event": {
                "event_type": "tool.before", "source": "test", "agent_id": "main", "session_key": session,
                "tool": {"name": "exec", "kind": "shell", "input_kind": "powershell"},
                "params": {"command": command},
            },
        }

    def test_ui_assets_spa_fallback_and_security_headers(self) -> None:
        root = self.client.get("/ui/")
        route = self.client.get("/ui/overview")
        self.assertEqual(root.status_code, 200)
        self.assertEqual(route.status_code, 200)
        self.assertIn("GuardAgent", root.text)
        self.assertIn('name="guard-csp-nonce"', root.text)
        self.assertIn("style-src-elem 'self' 'nonce-", root.headers["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", root.headers["content-security-policy"])
        self.assertEqual(root.headers["x-content-type-options"], "nosniff")
        asset_name = next((ROOT / "guardd" / "ui" / "static" / "assets").glob("*.css")).name
        asset = self.client.get(f"/ui/assets/{asset_name}")
        self.assertEqual(asset.status_code, 200)
        self.assertIn("immutable", asset.headers["cache-control"])
        self.assertEqual(self.client.get("/ui/not-a-real.js").status_code, 404)
        api_missing = self.client.get("/v1/ui/not-a-real-api")
        self.assertEqual(api_missing.status_code, 404)
        self.assertEqual(api_missing.json()["error"]["code"], "NOT_FOUND")
        openapi = self.client.get("/openapi.json").json()
        self.assertIn("PageResponse", openapi["components"]["schemas"])
        self.assertIn("UiErrorEnvelope", openapi["components"]["schemas"])

    def test_ui_internal_errors_use_structured_safe_response(self) -> None:
        with patch.object(self.client.app.state.service.store, "overview_metrics", side_effect=RuntimeError("secret detail")):
            response = self.client.get("/v1/ui/overview", headers={"X-Request-ID": "internal-test"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"]["code"], "INTERNAL_ERROR")
        self.assertEqual(response.json()["error"]["request_id"], "internal-test")
        self.assertNotIn("secret detail", response.text)

    def test_bootstrap_is_single_use_and_token_never_returned(self) -> None:
        replay = self.client.post(
            "/v1/ui/auth/session",
            headers={"Origin": self.origin},
            json={"schema_version": "1.0", "request_id": "replay", "code": self.bootstrap_code},
        )
        self.assertEqual(replay.status_code, 401)
        self.assertNotIn(self.token, replay.text)
        cookie = self.client.cookies.get("guard_ui_session")
        self.assertTrue(cookie)
        set_cookie = self.session_response.headers["set-cookie"].lower()
        self.assertIn("httponly", set_cookie)
        self.assertIn("samesite=strict", set_cookie)
        current = self.client.get("/v1/ui/auth/session")
        self.assertEqual(current.status_code, 200)
        self.assertNotIn(self.token, current.text)

    def test_csrf_and_origin_are_required_for_writes(self) -> None:
        policy = self.client.get("/v1/ui/policy").json()["item"]["text"]
        body = {"schema_version": "1.0", "request_id": "validate", "policy": policy}
        self.assertEqual(self.client.post("/v1/ui/policy/validate", json=body).status_code, 403)
        self.assertEqual(self.client.post("/v1/ui/policy/validate", headers={"Origin": "https://evil.example", "X-Guard-CSRF": self.csrf}, json=body).status_code, 403)
        self.assertEqual(self.client.post("/v1/ui/policy/validate", headers=self.write_headers, json=body).status_code, 200)

    def test_event_overview_detail_session_and_replay(self) -> None:
        decision = self.client.post("/v1/decisions/tool", headers=self.machine_auth, json=self.event("git status", "timeline")).json()
        self.assertEqual(decision["decision"], "ALLOW")
        overview = self.client.get("/v1/ui/overview?range=24h")
        self.assertEqual(overview.status_code, 200)
        self.assertGreaterEqual(overview.json()["metrics"]["events"], 1)
        events = self.client.get("/v1/ui/events?session_key=timeline")
        self.assertEqual(len(events.json()["items"]), 1)
        event_id = events.json()["items"][0]["event_id"]
        detail = self.client.get(f"/v1/ui/events/{event_id}").json()["item"]
        self.assertIn("event_hash", detail)
        self.assertEqual(detail["event"]["params"]["command"]["type"], "string")
        sessions = self.client.get("/v1/ui/sessions").json()["items"]
        self.assertIn("timeline", {item["session_key"] for item in sessions})
        replay = self.client.post(
            "/v1/ui/sessions/timeline/replay", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "replay"},
        )
        self.assertEqual(replay.status_code, 200)
        replay_item = replay.json()["item"]
        self.assertEqual(replay_item["source"], "session")
        self.assertEqual(replay_item["evidence"], "recorded_sanitized_normalized")
        self.assertEqual(len(replay_item["results"]), 1)
        self.assertEqual(replay_item["results"][0]["decision"], "ALLOW")
        self.assertIn("GIT-READ-001", replay_item["results"][0]["rule_ids"])

    def test_event_combination_filters_and_cursor_paging(self) -> None:
        self.client.post("/v1/decisions/tool", headers=self.machine_auth, json=self.event("git status", "filter-a"))
        self.client.post("/v1/decisions/tool", headers=self.machine_auth, json=self.event("git push origin main", "filter-b"))
        first = self.client.get("/v1/ui/events?limit=1")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(len(first.json()["items"]), 1)
        self.assertTrue(first.json()["next_cursor"])
        second = self.client.get("/v1/ui/events", params={"limit": 1, "cursor": first.json()["next_cursor"]})
        self.assertEqual(second.status_code, 200)
        self.assertNotEqual(first.json()["items"][0]["event_id"], second.json()["items"][0]["event_id"])
        filtered = self.client.get("/v1/ui/events?agent=main&tool=exec&session_key=filter-b&has_approval=true")
        self.assertEqual(len(filtered.json()["items"]), 1)
        self.assertEqual(filtered.json()["items"][0]["session_key"], "filter-b")
        self.assertTrue(filtered.json()["items"][0]["has_approval"])

    def test_session_detail_contains_io_and_risk_summaries(self) -> None:
        event = self.event("ignored", "session-summary")
        event["event"]["tool"] = {"name": "write", "kind": "filesystem", "input_kind": "text"}
        event["event"]["params"] = {"path": "notes.txt", "content": "0123456789"}
        response = self.client.post("/v1/decisions/tool", headers=self.machine_auth, json=event)
        self.assertEqual(response.status_code, 200)
        detail = self.client.get("/v1/ui/sessions/session-summary")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["item"]["io_summary"]["write_bytes"], 10)
        self.assertGreaterEqual(detail.json()["item"]["risk_score"], 0)

    def test_session_task_policy_can_be_reviewed_and_activated_in_ui(self) -> None:
        captured = self.client.post(
            "/v1/task-policies/capture", headers=self.machine_auth,
            json={
                "schema_version": "1.0", "request_id": "capture-task", "session_key": "ui-task",
                "agent_id": "main", "prompt": "保存到 reports/ui.md",
            },
        )
        self.assertEqual(captured.status_code, 200)
        candidate = captured.json()
        view = self.client.get("/v1/ui/sessions/ui-task/task-policy")
        self.assertEqual(view.status_code, 200)
        self.assertEqual(view.json()["item"]["candidate"]["policy_digest"], candidate["policy_digest"])
        self.assertTrue(view.json()["item"]["diff"]["tools_allow"]["added"])

        activated = self.client.post(
            "/v1/ui/sessions/ui-task/task-policy/activate", headers=self.write_headers,
            json={
                "schema_version": "1.0", "request_id": "activate-task",
                "candidate_digest": candidate["policy_digest"], "expected_active_revision": None,
            },
        )
        self.assertEqual(activated.status_code, 200)
        self.assertEqual(activated.json()["item"]["status"], "active")
        updated = self.client.get("/v1/ui/sessions/ui-task/task-policy").json()["item"]
        self.assertIsNone(updated["candidate"])
        self.assertEqual(updated["active"]["revision"], 1)

    def test_content_inspection_and_sanitization_views_expose_metadata_only(self) -> None:
        skill = self.root / "review-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("Use subprocess.run with git status.", encoding="utf-8")
        inspected = self.client.post(
            "/v1/inspections/skill", headers=self.machine_auth,
            json={
                "schema_version": "1.0", "request_id": "inspect-ui", "source_path": str(skill),
                "canonical_name": "review-skill", "source_identity": "ui-test", "builtin_findings": [],
            },
        )
        self.assertEqual(inspected.status_code, 200)
        digest = inspected.json()["content_digest"]
        listed = self.client.get("/v1/ui/inspections").json()["items"]
        self.assertIn(digest, {item["content_digest"] for item in listed})
        detail = self.client.get(f"/v1/ui/inspections/{digest}")
        self.assertEqual(detail.status_code, 200)
        approved = self.client.post(
            f"/v1/ui/inspections/{digest}/confirm", headers=self.write_headers,
            json={
                "schema_version": "1.0", "request_id": "approve-inspection", "operator": "ignored",
                "decision": "approve", "scope": "allow-this-digest",
            },
        )
        self.assertEqual(approved.status_code, 200)

        self.client.post(
            "/v1/events/sanitization", headers=self.machine_auth,
            json={
                "schema_version": "1.0", "request_id": "san-ui", "sanitizer_event_id": "san-ui",
                "direction": "inbound", "session_key": "sha256:ui", "tool_name": "web_fetch",
                "classifications": ["token"], "transformations": [], "original_size": 20,
                "result_size": 10, "truncated": False, "blocked": False,
            },
        )
        events = self.client.get("/v1/ui/sanitization/events").json()["items"]
        self.assertEqual(events[0]["classifications"], ["token"])
        self.assertNotIn("raw", self.client.get("/v1/ui/sanitization/events").text.lower())

    def test_approval_resolution_is_single_winner(self) -> None:
        decision = self.client.post("/v1/decisions/tool", headers=self.machine_auth, json=self.event("git push origin main", "approval-ui")).json()
        approval_id = decision["approval_id"]
        detail = self.client.get(f"/v1/ui/approvals/{approval_id}")
        self.assertEqual(detail.status_code, 200)
        resolved = self.client.post(
            f"/v1/ui/approvals/{approval_id}/allow-once", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "allow"},
        )
        self.assertEqual(resolved.status_code, 200)
        self.assertEqual(resolved.json()["item"]["status"], "allowed_once")
        losing = self.client.post(
            f"/v1/ui/approvals/{approval_id}/deny", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "deny"},
        )
        self.assertEqual(losing.status_code, 409)

    def test_policy_candidate_simulation_publish_revision_and_restore(self) -> None:
        current = self.client.get("/v1/ui/policy").json()["item"]
        candidate_document = yaml.safe_load(current["text"])
        candidate_document["defaults"]["mode"] = "approval"
        candidate = yaml.safe_dump(candidate_document, sort_keys=False)
        validation = self.client.post(
            "/v1/ui/policy/validate", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "validate", "policy": candidate},
        )
        self.assertTrue(validation.json()["item"]["valid"])
        regression = self.client.post(
            "/v1/ui/policy/regression", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "regression", "policy": candidate},
        )
        self.assertEqual(regression.status_code, 200)
        self.assertTrue(regression.json()["item"]["passed"])
        self.assertGreaterEqual(regression.json()["item"]["total"], 30)
        self.assertEqual(regression.json()["item"]["failed"], 0)
        before = self.client.get("/v1/status", headers=self.machine_auth).json()["events"]
        simulation = self.client.post(
            "/v1/ui/policy/simulate", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "simulate", "policy": candidate, "event": self.event("git push origin main")["event"]},
        )
        self.assertEqual(simulation.status_code, 200)
        self.assertTrue(simulation.json()["item"]["dry_run"])
        self.assertEqual(self.client.get("/v1/status", headers=self.machine_auth).json()["events"], before)
        published = self.client.post(
            "/v1/ui/policy/publish", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "publish", "policy": candidate, "expected_digest": current["digest"], "comment": "integration test"},
        )
        self.assertEqual(published.status_code, 200)
        new_digest = published.json()["item"]["digest"]
        self.assertNotEqual(new_digest, current["digest"])
        revisions = self.client.get("/v1/ui/policy/revisions").json()["items"]
        self.assertEqual(revisions[0]["digest"], new_digest)
        snapshot = next(item for item in revisions if item["digest"] == current["digest"])
        conflict = self.client.post(
            "/v1/ui/policy/publish", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "conflict", "policy": candidate, "expected_digest": current["digest"]},
        )
        self.assertEqual(conflict.status_code, 409)
        restored = self.client.post(
            f"/v1/ui/policy/revisions/{snapshot['revision_id']}/restore", headers=self.write_headers,
            json={"schema_version": "1.0", "request_id": "restore", "expected_digest": new_digest, "confirmation": "ENFORCE"},
        )
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.json()["item"]["digest"], current["digest"])
        self.assertEqual(self.policy_path.read_text(encoding="utf-8"), current["text"])
        store = self.client.app.state.service.store
        with store._lock:
            restore_actions = store._connection.execute("SELECT count(*) FROM operator_actions WHERE action='policy.restore'").fetchone()[0]
        self.assertEqual(restore_actions, 1)

    def test_settings_never_expose_token_and_invalid_cursor_is_rejected(self) -> None:
        settings = self.client.get("/v1/ui/settings")
        self.assertEqual(settings.status_code, 200)
        self.assertNotIn(self.token, settings.text)
        override_token = ensure_token(self.settings.security_override_token_path)
        self.assertNotIn(override_token, settings.text)
        self.assertNotIn("token_path", settings.text)
        self.assertNotIn("api_key", settings.text)
        self.assertEqual(self.client.get("/v1/ui/events?cursor=invalid").status_code, 422)

    def test_ui_can_be_disabled_without_disabling_machine_api(self) -> None:
        disabled = replace(self.settings, state_dir=self.policy_path.parent / "disabled-state", ui_enabled=False)
        with TestClient(create_app(disabled)) as client:
            self.assertEqual(client.get("/v1/health").status_code, 200)
            self.assertEqual(client.get("/ui/").status_code, 503)
            self.assertEqual(client.post("/v1/ui/auth/bootstrap", headers={"Authorization": f"Bearer {ensure_token(disabled.token_path)}"}, json={"schema_version": "1.0", "request_id": "disabled"}).status_code, 404)

    def test_diagnostics_run_in_background(self) -> None:
        report = {"overall": "pass", "checks": [{"name": "test", "status": "pass", "message": "ok", "output": None}]}
        with patch("guardd.diagnostics.jobs.run_doctor", return_value=report):
            started = self.client.post(
                "/v1/ui/diagnostics/jobs", headers=self.write_headers,
                json={"schema_version": "1.0", "request_id": "doctor"},
            )
            self.assertEqual(started.status_code, 200)
            job_id = started.json()["item"]["job_id"]
            result = None
            for _ in range(50):
                result = self.client.get(f"/v1/ui/diagnostics/jobs/{job_id}").json()["item"]
                if result["status"] in {"completed", "failed"}:
                    break
                time.sleep(0.01)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["result"]["overall"], "pass")
            history = self.client.get("/v1/ui/diagnostics/jobs")
            self.assertEqual(history.status_code, 200)
            self.assertEqual(history.json()["items"][0]["job_id"], job_id)
            self.assertEqual(history.json()["items"][0]["result"]["overall"], "pass")


if __name__ == "__main__":
    unittest.main()
