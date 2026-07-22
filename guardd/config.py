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
    task_policy_enabled: bool = True
    task_policy_mode: str = "observe"
    task_policy_ttl_minutes: int = 120
    task_policy_out_of_scope: str = "require_approval"
    sanitization_enabled: bool = True
    sanitization_mode: str = "observe"
    sanitization_max_result_bytes: int = 1_048_576
    content_inspection_enabled: bool = True
    content_inspection_mode: str = "observe"

    @classmethod
    def from_env(cls) -> "Settings":
        host = os.getenv("GUARDD_HOST", "127.0.0.1")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("GUARDD_HOST must be loopback")
        task_policy_mode = os.getenv("GUARD_TASK_POLICY_MODE", "observe").strip().lower()
        if task_policy_mode not in {"observe", "approval", "enforce"}:
            raise ValueError("GUARD_TASK_POLICY_MODE must be observe, approval, or enforce")
        task_policy_out_of_scope = os.getenv("GUARD_TASK_POLICY_OUT_OF_SCOPE", "require_approval").strip().lower()
        if task_policy_out_of_scope not in {"require_approval", "deny"}:
            raise ValueError("GUARD_TASK_POLICY_OUT_OF_SCOPE must be require_approval or deny")
        sanitization_mode = os.getenv("GUARD_SANITIZATION_MODE", "observe").strip().lower()
        if sanitization_mode not in {"disabled", "observe", "enforce"}:
            raise ValueError("GUARD_SANITIZATION_MODE must be disabled, observe, or enforce")
        content_inspection_mode = os.getenv("GUARD_CONTENT_INSPECTION_MODE", "observe").strip().lower()
        if content_inspection_mode not in {"disabled", "observe", "enforce"}:
            raise ValueError("GUARD_CONTENT_INSPECTION_MODE must be disabled, observe, or enforce")
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
            task_policy_enabled=_env_bool("GUARD_TASK_POLICY_ENABLED", True),
            task_policy_mode=task_policy_mode,
            task_policy_ttl_minutes=max(1, min(int(os.getenv("GUARD_TASK_POLICY_TTL_MINUTES", "120")), 1440)),
            task_policy_out_of_scope=task_policy_out_of_scope,
            sanitization_enabled=_env_bool("GUARD_SANITIZATION_ENABLED", True),
            sanitization_mode=sanitization_mode,
            sanitization_max_result_bytes=max(
                16_384, min(int(os.getenv("GUARD_SANITIZATION_MAX_RESULT_BYTES", "1048576")), 16_777_216),
            ),
            content_inspection_enabled=_env_bool("GUARD_CONTENT_INSPECTION_ENABLED", True),
            content_inspection_mode=content_inspection_mode,
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

    @property
    def hmac_key_path(self) -> Path:
        return self.state_dir / "guardd.hmac"
