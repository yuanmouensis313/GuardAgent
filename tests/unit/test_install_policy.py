from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "openclaw_install_policy.py"


class InstallPolicyTests(unittest.TestCase):
    def invoke(self, target: str, specifier: str = "", source: dict | None = None, allowlist: str = "guard-openclaw", network: bool = False) -> dict:
        source_path = str(ROOT)
        request = {
            "protocolVersion": 1, "targetType": "plugin", "targetName": target,
            "source": source or {"kind": "local-path", "mutable": False, "network": False},
            "sourcePath": source_path,
            "origin": {"registry": "https://registry.npmjs.org", "version": "1.2.3"},
            "request": {"requestedSpecifier": specifier},
        }
        env = dict(os.environ, GUARD_INSTALL_ALLOWLIST=allowlist, GUARD_INSTALL_LOCAL_ROOTS=str(ROOT), GUARD_INSTALL_REGISTRIES="registry.npmjs.org")
        result = subprocess.run([sys.executable, str(SCRIPT), "--json"], input=json.dumps(request), text=True, capture_output=True, env=env, timeout=5)
        self.assertIn(result.returncode, {0, 2})
        return json.loads(result.stdout)

    def test_exact_allowlist_allows_local_guard_plugin(self) -> None:
        self.assertEqual(self.invoke("guard-openclaw")["decision"], "allow")

    def test_unknown_target_is_blocked(self) -> None:
        self.assertEqual(self.invoke("untrusted")["decision"], "block")

    def test_network_source_requires_exact_immutable_version(self) -> None:
        source = {"kind": "npm", "mutable": False, "network": True}
        self.assertEqual(self.invoke("trusted", "npm:trusted@latest", source, "trusted")["decision"], "block")
        self.assertEqual(self.invoke("trusted", "npm:trusted@1.2.3", source, "trusted")["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
