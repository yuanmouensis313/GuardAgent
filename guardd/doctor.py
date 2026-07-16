from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from guardd.config import Settings


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
