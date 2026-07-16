from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _default_state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "GuardAgent"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "guardagent"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    state_dir: Path = _default_state_dir()
    policy_path: Path = Path("policies/default.yaml")
    workspace: Path = Path.cwd()
    request_limit_bytes: int = 1_048_576
    approval_ttl_seconds: int = 60
    audit_retention_days: int = 30
    plugin_timeout_ms: int = 400
    ui_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        host = os.getenv("GUARDD_HOST", "127.0.0.1")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("GUARDD_HOST must be loopback")
        return cls(
            host=host,
            port=int(os.getenv("GUARDD_PORT", "8787")),
            state_dir=Path(os.getenv("GUARD_AGENT_STATE_DIR", _default_state_dir())).expanduser(),
            policy_path=Path(os.getenv("GUARD_AGENT_POLICY", "policies/default.yaml")).expanduser(),
            workspace=Path(os.getenv("GUARD_AGENT_WORKSPACE", Path.cwd())).expanduser().resolve(),
            request_limit_bytes=int(os.getenv("GUARDD_REQUEST_LIMIT", "1048576")),
            approval_ttl_seconds=max(1, min(int(os.getenv("GUARDD_APPROVAL_TTL", "60")), 600)),
            audit_retention_days=int(os.getenv("GUARDD_RETENTION_DAYS", "30")),
            plugin_timeout_ms=int(os.getenv("GUARDD_PLUGIN_TIMEOUT_MS", "400")),
            ui_enabled=_env_bool("GUARDD_UI_ENABLED", True),
        )

    @property
    def db_path(self) -> Path:
        return self.state_dir / "guardagent.sqlite3"

    @property
    def token_path(self) -> Path:
        return self.state_dir / "guardd.token"

    @property
    def emergency_log_path(self) -> Path:
        return self.state_dir / "emergency.jsonl"
