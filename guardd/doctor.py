from __future__ import annotations

import json
import shutil
import subprocess
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


def _run(name: str, command: list[str], critical: bool = True) -> Check:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Check(name, "fail" if critical else "warn", str(exc))
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return Check(name, "pass" if result.returncode == 0 else ("fail" if critical else "warn"), f"exit code {result.returncode}", output[-4000:])


def run_doctor(settings: Settings) -> dict[str, Any]:
    checks: list[Check] = []
    if shutil.which("openclaw") is None:
        checks.append(Check("openclaw-installed", "fail", "OpenClaw CLI is not installed or not on PATH"))
    else:
        checks.extend([
            _run("openclaw-doctor", ["openclaw", "doctor"]),
            _run("security-audit", ["openclaw", "security", "audit"]),
            _run("security-audit-deep", ["openclaw", "security", "audit", "--deep"]),
            _run("sandbox-explain", ["openclaw", "sandbox", "explain", "--agent", "main"]),
            _run("exec-policy", ["openclaw", "exec-policy", "show"]),
            _run("approvals", ["openclaw", "approvals", "get"]),
        ])
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
