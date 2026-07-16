from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from guardd.normalizers.command import normalize_command
from guardd.normalizers.network import normalize_network_targets
from guardd.normalizers.path import normalize_paths
from guardd.security import build_extra_patterns, digest_payload, redact_text, sanitize


class CommandNormalizerTests(unittest.TestCase):
    def test_splits_shell_operators_and_takes_each_command(self) -> None:
        result = normalize_command("git status && rm -rf ../backup | tee out.txt", "bash")
        self.assertEqual([item["executable"] for item in result["commands"]], ["git", "rm", "tee"])
        self.assertEqual(result["shell_features"], ["and", "pipeline"])

    def test_detects_inline_eval_and_encoded_powershell(self) -> None:
        self.assertTrue(normalize_command("python -c 'print(1)'", "bash")["dynamic_eval"])
        self.assertTrue(normalize_command("powershell -EncodedCommand ZQB2AGkAbAA=", "powershell")["dynamic_eval"])

    def test_unclosed_quote_fails_parse(self) -> None:
        self.assertTrue(normalize_command('echo "unterminated', "bash")["parse_failed"])

    def test_redirection_and_environment_keys(self) -> None:
        command = normalize_command("TOKEN=x tool > ../out.txt", "bash")["commands"][0]
        self.assertIn("../out.txt", command["redirections"])
        self.assertIn("TOKEN", command["environment_keys"])

    def test_reports_expansion_substitution_and_wildcards(self) -> None:
        result = normalize_command("echo $HOME $(whoami) *.txt", "bash")
        self.assertTrue(result["variable_expansion"])
        self.assertTrue(result["command_substitution"])
        self.assertTrue(result["wildcards"])


class PathNormalizerTests(unittest.TestCase):
    def test_dotdot_escape_is_external(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            result = normalize_paths({"path": "../secret.txt"}, workspace, "write")
            self.assertEqual(result[0]["path_group"], "unknown_external")

    def test_symlink_escape_is_external_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            outside = root / "outside"
            workspace.mkdir()
            outside.mkdir()
            link = workspace / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is not permitted")
            result = normalize_paths({"path": "linked/file.txt"}, workspace, "write")
            self.assertEqual(result[0]["path_group"], "unknown_external")

    def test_sensitive_path_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            result = normalize_paths({"path": ".env"}, workspace, "read")
            self.assertEqual(result[0]["path_group"], "sensitive_read_denied")

    def test_apply_patch_paths_are_canonicalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            result = normalize_paths({"patch": "*** Begin Patch\n*** Update File: ../outside.py\n*** End Patch"}, workspace, "apply_patch")
            self.assertEqual(result[0]["path_group"], "unknown_external")


class NetworkAndSecretTests(unittest.TestCase):
    def test_network_classification_and_query_redaction(self) -> None:
        result = normalize_network_targets(
            {"url": "https://new.example/path?token=secret"},
            allowlist=["docs.openclaw.ai"], denylist=["evil.example"], resolve_dns=False,
        )[0]
        self.assertEqual(result["classification"], "new_public")
        self.assertNotIn("secret", result["sanitized_url"])

    def test_loopback_private_direct_and_denied(self) -> None:
        cases = {
            "http://127.0.0.1/x": "loopback",
            "http://192.168.1.5/x": "private",
            "https://8.8.8.8/x": "direct_ip",
            "https://evil.example/x": "denied",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(normalize_network_targets({"url": url}, denylist=["evil.example"], resolve_dns=False)[0]["classification"], expected)

    def test_dns_failure_and_private_resolution_fail_closed(self) -> None:
        with patch("guardd.normalizers.network._resolve", return_value=None):
            self.assertEqual(normalize_network_targets({"url": "https://unknown.example"})[0]["classification"], "unresolved")
        with patch("guardd.normalizers.network._resolve", return_value=["127.0.0.1"]):
            self.assertEqual(normalize_network_targets({"url": "https://public.example"})[0]["classification"], "dns_private")

    def test_secret_redaction_keeps_only_marker(self) -> None:
        secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
        redacted, kinds = redact_text(f"token={secret}")
        self.assertNotIn(secret, redacted)
        self.assertIn("github_token", kinds)
        self.assertIn("sha256=", redacted)

    def test_sensitive_key_is_redacted(self) -> None:
        clean, kinds = sanitize({"Authorization": "Bearer raw-value"})
        self.assertNotIn("raw-value", str(clean))
        self.assertEqual(kinds, ["sensitive_field"])

    def test_configurable_phone_and_custom_patterns(self) -> None:
        patterns = build_extra_patterns({"detect_phone": True, "custom_patterns": [{"id": "employee_id", "regex": "EMP-[0-9]{4}"}]})
        clean, kinds = sanitize("call 13800138000 about EMP-1234", extra_patterns=patterns)
        self.assertNotIn("13800138000", clean)
        self.assertNotIn("EMP-1234", clean)
        self.assertEqual(kinds, ["employee_id", "phone"])

    def test_digest_is_canonical(self) -> None:
        self.assertEqual(digest_payload({"a": 1, "b": 2}), digest_payload({"b": 2, "a": 1}))
        self.assertNotEqual(digest_payload({"a": 1}), digest_payload({"a": 2}))


if __name__ == "__main__":
    unittest.main()
