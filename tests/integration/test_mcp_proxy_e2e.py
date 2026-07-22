from __future__ import annotations

import json
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import httpx
import uvicorn

from guardd.api import create_app
from guardd.config import Settings
from guardd.security import ensure_token


ROOT = Path(__file__).parents[2]


class McpProxyEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        workspace = root / "workspace"
        workspace.mkdir()
        self.settings = Settings(
            state_dir=root / "state", policy_path=ROOT / "policies" / "default.yaml",
            workspace=workspace, task_policy_enabled=False,
        )
        self.token = ensure_token(self.settings.token_path)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(128)
        port = self.socket.getsockname()[1]
        self.base_url = f"http://127.0.0.1:{port}"
        config = uvicorn.Config(create_app(self.settings), log_level="error", access_log=False)
        self.server = uvicorn.Server(config)
        self.server_thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True,
        )
        self.server_thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        if not self.server.started:
            self.fail("test guardd server did not start")

    def tearDown(self) -> None:
        self.server.should_exit = True
        self.server_thread.join(timeout=10)
        self.socket.close()
        self.temp.cleanup()

    def test_stdio_proxy_filters_descriptors_binds_call_and_sanitizes_result(self) -> None:
        command = [
            sys.executable, "-m", "guardd.mcp_proxy",
            "--server-identity", "fixture-server",
            "--guardd-url", self.base_url,
            "--token-file", str(self.settings.token_path),
            "--session-key", "proxy-e2e", "--mode", "observe", "--",
            sys.executable, str(ROOT / "tests" / "fixtures" / "mcp_fake_server.py"),
        ]
        process = subprocess.Popen(
            command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
        )
        assert process.stdin is not None and process.stdout is not None
        lines: queue.Queue[str | None] = queue.Queue()

        def pump() -> None:
            for line in process.stdout:
                lines.put(line)
            lines.put(None)

        threading.Thread(target=pump, daemon=True).start()

        def exchange(message: dict) -> dict:
            process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            process.stdin.flush()
            raw = lines.get(timeout=10)
            self.assertIsNotNone(raw, "proxy exited before returning a response")
            return json.loads(raw or "{}")

        try:
            initialized = exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            self.assertEqual(initialized["result"]["serverInfo"]["version"], "1.0")

            listed = exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            self.assertEqual([item["name"] for item in listed["result"]["tools"]], ["search_docs"])

            called = exchange({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"query": "security"}},
            })
            serialized = json.dumps(called, ensure_ascii=False)
            self.assertNotIn("sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456", serialized)
            self.assertIn("GUARD_REDACTED", serialized)
            self.assertIn("UNTRUSTED_TOOL_CONTENT", serialized)

            events = httpx.get(
                f"{self.base_url}/v1/sanitization/events",
                headers={"Authorization": f"Bearer {self.token}"}, timeout=5,
            ).json()
            self.assertTrue(events)
            self.assertIn("openai_key", events[0]["classifications"])
            self.assertTrue(events[0]["transformations"])
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    unittest.main()
