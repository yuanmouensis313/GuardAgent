from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from guardd.config import Settings
from guardd.security import SANITIZATION_PATTERN_DIGEST


@dataclass
class Check:
    name: str
    status: str
    message: str
    output: str | None = None
    duration_ms: float = 0.0


def _run(name: str, command: list[str], critical: bool = True, timeout_seconds: float = 20.0) -> Check:
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=max(0.1, min(timeout_seconds, 20.0)), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Check(name, "fail" if critical else "warn", str(exc), duration_ms=round((time.monotonic() - started) * 1000, 1))
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return Check(name, "pass" if result.returncode == 0 else ("fail" if critical else "warn"), f"exit code {result.returncode}", output[-4000:], round((time.monotonic() - started) * 1000, 1))


def run_doctor(settings: Settings) -> dict[str, Any]:
    checks: list[Check] = []
    deadline = time.monotonic() + 60.0
    if shutil.which("openclaw") is None:
        checks.append(Check("openclaw-installed", "fail", "OpenClaw CLI is not installed or not on PATH"))
    else:
        commands = [
            ("openclaw-doctor", ["openclaw", "doctor"]),
            ("security-audit", ["openclaw", "security", "audit"]),
            ("security-audit-deep", ["openclaw", "security", "audit", "--deep"]),
            ("sandbox-explain", ["openclaw", "sandbox", "explain", "--agent", "main"]),
            ("exec-policy", ["openclaw", "exec-policy", "show"]),
            ("approvals", ["openclaw", "approvals", "get"]),
        ]
        for name, command in commands:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                checks.append(Check(name, "fail", "doctor total timeout exceeded; check was not started"))
            else:
                checks.append(_run(name, command, timeout_seconds=remaining))
    checks.append(Check("loopback-bind", "pass" if settings.host in {"127.0.0.1", "::1", "localhost"} else "fail", settings.host))
    checks.append(Check("policy-file", "pass" if settings.policy_path.is_file() else "fail", str(settings.policy_path)))
    checks.append(Check("token-file", "pass" if settings.token_path.is_file() else "warn", str(settings.token_path)))
    checks.append(Check(
        "security-override-token-file",
        "pass" if settings.security_override_token_path.is_file() else "warn",
        str(settings.security_override_token_path),
    ))
    root = Path(__file__).parents[1]
    generated_patterns = root / "plugins" / "guard-openclaw" / "src" / "generated-sanitization-patterns.ts"
    pattern_source_available = generated_patterns.is_file()
    pattern_match = pattern_source_available and SANITIZATION_PATTERN_DIGEST in generated_patterns.read_text(encoding="utf-8")
    checks.append(Check(
        "sanitization-pattern-parity",
        "pass" if pattern_match else "fail" if pattern_source_available else "warn",
        SANITIZATION_PATTERN_DIGEST if pattern_source_available else "repository TypeScript source is unavailable in this installed package; verify parity in CI",
    ))
    plugin_index = root / "plugins" / "guard-openclaw" / "src" / "index.ts"
    plugin_source_available = plugin_index.is_file()
    hook_source = plugin_index.read_text(encoding="utf-8") if plugin_source_available else ""
    hooks_present = "tool_result_persist" in hook_source and "before_message_write" in hook_source
    checks.append(Check(
        "model-path-sanitization-hooks",
        "pass" if hooks_present else "fail" if plugin_source_available else "warn",
        "tool_result_persist + before_message_write" if hooks_present else
        "required synchronous hooks are missing" if plugin_source_available else
        "repository plugin source is unavailable in this installed package; validate the installed plugin separately",
    ))
    proxy_available = (root / "guardd" / "mcp_proxy.py").is_file()
    checks.append(Check(
        "mcp-descriptor-gate", "pass" if proxy_available else "fail",
        "guard-mcp-proxy available; current OpenClaw SDK has no descriptor registration hook" if proxy_available else "MCP proxy is missing",
    ))
    if settings.db_path.exists():
        checks.append(Check("state-outside-workspace", "fail" if _inside(settings.db_path, settings.workspace) else "pass", str(settings.db_path)))
    overall = "pass" if all(item.status == "pass" for item in checks) else "fail" if any(item.status == "fail" for item in checks) else "warn"
    return {"overall": overall, "checks": [asdict(item) for item in checks]}


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
