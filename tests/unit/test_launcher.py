from __future__ import annotations

import io
import os
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import httpx

from guardd.bootstrap import initialize
from guardd.config import Settings
from guardd.launcher import ServiceProbe, launch, main, probe_service


ROOT = Path(__file__).parents[2]
POLICY = ROOT / "policies" / "default.yaml"


class BootstrapTests(unittest.TestCase):
    def settings(self, state_dir: Path) -> Settings:
        return Settings(
            state_dir=state_dir,
            policy_path=POLICY,
            workspace=ROOT,
        )

    def test_initialize_creates_and_reuses_all_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = self.settings(Path(temporary) / "state")
            policy = initialize(settings)
            paths = (
                settings.token_path,
                settings.security_override_token_path,
                settings.hmac_key_path,
            )
            original = {path: path.read_bytes() for path in paths}

            second_policy = initialize(settings)

            self.assertEqual(policy.digest, second_policy.digest)
            self.assertTrue(all(path.is_file() for path in paths))
            self.assertEqual(original, {path: path.read_bytes() for path in paths})

    def test_invalid_policy_does_not_create_state_or_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = Settings(
                state_dir=root / "state",
                policy_path=root / "missing-policy.yaml",
                workspace=ROOT,
            )

            with self.assertRaises(OSError):
                initialize(settings)

            self.assertFalse(settings.state_dir.exists())


class LauncherTests(unittest.TestCase):
    def settings(self, state_dir: Path, port: int = 18787) -> Settings:
        return Settings(
            port=port,
            state_dir=state_dir,
            policy_path=POLICY,
            workspace=ROOT,
        )

    def test_probe_recognizes_guardagent(self) -> None:
        response = Mock(status_code=200)
        response.json.return_value = {"status": "ok", "schema_version": "1.0"}
        with patch("guardd.launcher._port_is_available", return_value=False):
            with patch("guardd.launcher.httpx.Client.get", return_value=response):
                self.assertIs(probe_service(self.settings(Path("state"))), ServiceProbe.GUARDAGENT)

    def test_probe_uses_bind_to_recognize_available_port(self) -> None:
        with patch("guardd.launcher._port_is_available", return_value=True):
            with patch("guardd.launcher.httpx.Client.get") as request:
                self.assertIs(probe_service(self.settings(Path("state"))), ServiceProbe.AVAILABLE)
        request.assert_not_called()

    def test_probe_treats_connection_refusal_as_available(self) -> None:
        request = httpx.Request("GET", "http://127.0.0.1:18787/v1/health")
        with patch("guardd.launcher._port_is_available", return_value=False):
            with patch(
                "guardd.launcher.httpx.Client.get",
                side_effect=httpx.ConnectError("connection refused", request=request),
            ):
                self.assertIs(probe_service(self.settings(Path("state"))), ServiceProbe.AVAILABLE)

    def test_probe_treats_other_response_as_occupied(self) -> None:
        response = Mock(status_code=200)
        response.json.return_value = ["not", "guardagent"]
        with patch("guardd.launcher._port_is_available", return_value=False):
            with patch("guardd.launcher.httpx.Client.get", return_value=response):
                self.assertIs(probe_service(self.settings(Path("state"))), ServiceProbe.OCCUPIED)

    def test_existing_service_does_not_start_another_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Mock()
            output = io.StringIO()
            with patch("guardd.launcher.probe_service", return_value=ServiceProbe.GUARDAGENT):
                with redirect_stdout(output):
                    status = launch(self.settings(Path(temporary) / "state"), runner)

            self.assertEqual(status, 0)
            runner.assert_not_called()
            self.assertIn("already running", output.getvalue())

    def test_occupied_port_fails_without_starting_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Mock()
            with patch("guardd.launcher.probe_service", return_value=ServiceProbe.OCCUPIED):
                with self.assertRaisesRegex(RuntimeError, "already in use"):
                    launch(self.settings(Path(temporary) / "state"), runner)
            runner.assert_not_called()

    def test_normal_launch_prints_safe_summary_and_runs_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = self.settings(Path(temporary) / "state")
            runner = Mock()
            output = io.StringIO()
            with patch("guardd.launcher.probe_service", return_value=ServiceProbe.AVAILABLE):
                with redirect_stdout(output):
                    status = launch(settings, runner)

            token = settings.token_path.read_text(encoding="utf-8").strip()
            override_token = settings.security_override_token_path.read_text(encoding="utf-8").strip()
            text = output.getvalue()
            self.assertEqual(status, 0)
            runner.assert_called_once_with(settings)
            self.assertIn("uv run guardctl ui", text)
            self.assertNotIn(token, text)
            self.assertNotIn(override_token, text)

    def test_main_converts_known_startup_error_to_exit_one(self) -> None:
        error = io.StringIO()
        with patch("guardd.launcher.launch", side_effect=ValueError("bad setting")):
            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("bad setting", error.getvalue())

    def test_settings_reject_non_loopback_and_invalid_ports(self) -> None:
        with patch.dict(os.environ, {"GUARDD_HOST": "0.0.0.0"}):
            with self.assertRaisesRegex(ValueError, "loopback"):
                Settings.from_env()
        with patch.dict(os.environ, {"GUARDD_HOST": "127.0.0.1", "GUARDD_PORT": "70000"}):
            with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
                Settings.from_env()

    def test_console_script_entries_remain_registered(self) -> None:
        document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        scripts = document["project"]["scripts"]
        self.assertEqual(scripts["guardagent"], "guardd.launcher:main")
        self.assertEqual(scripts["guardd"], "guardd.main:main")
        self.assertEqual(scripts["guardctl"], "guardd.cli:app")
        self.assertEqual(scripts["guard-mcp-proxy"], "guardd.mcp_proxy:main")


if __name__ == "__main__":
    unittest.main()
