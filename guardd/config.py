from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _default_state_dir() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
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
    llm_enabled: bool = False
    llm_provider: str = "compatible_http"
    llm_model: str | None = None
    llm_base_url: str | None = None
    llm_api_key_env: str = "GUARD_LLM_API_KEY"
    llm_request_timeout_ms: int = 8000
    llm_connect_timeout_ms: int = 1000
    llm_max_input_bytes: int = 65_536
    llm_max_output_bytes: int = 16_384
    llm_max_output_tokens: int = 1500
    llm_max_concurrency: int = 2
    llm_queue_capacity: int = 256
    llm_cache_ttl_minutes: int = 60
    llm_circuit_breaker_failures: int = 5
    llm_circuit_breaker_cooldown_seconds: int = 60
    llm_review_mode: str = "disabled"
    llm_review_sample_allow_rate: float = 0.01
    llm_review_deny_confidence_threshold: float = 0.92
    llm_review_approval_confidence_threshold: float = 0.65
    task_policy_synthesizer: str = "deterministic"
    task_policy_model_timeout_ms: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        host = os.getenv("GUARDD_HOST", "127.0.0.1")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("GUARDD_HOST must be loopback")
        try:
            port = int(os.getenv("GUARDD_PORT", "8787"))
        except ValueError as exc:
            raise ValueError("GUARDD_PORT must be an integer between 1 and 65535") from exc
        if not 1 <= port <= 65_535:
            raise ValueError("GUARDD_PORT must be between 1 and 65535")
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
        llm_review_mode = os.getenv("GUARD_LLM_REVIEW_MODE", "disabled").strip().lower()
        if llm_review_mode not in {"disabled", "shadow", "advisory", "enforce_tighten"}:
            raise ValueError("GUARD_LLM_REVIEW_MODE must be disabled, shadow, advisory, or enforce_tighten")
        llm_provider = os.getenv("GUARD_LLM_PROVIDER", "compatible_http").strip().lower()
        if llm_provider not in {"compatible_http"}:
            raise ValueError("GUARD_LLM_PROVIDER must be compatible_http")
        task_policy_synthesizer = os.getenv("GUARD_TASK_POLICY_SYNTHESIZER", "deterministic").strip().lower()
        if task_policy_synthesizer not in {"deterministic", "hybrid"}:
            raise ValueError("GUARD_TASK_POLICY_SYNTHESIZER must be deterministic or hybrid")
        llm_sample_allow_rate = float(os.getenv("GUARD_LLM_REVIEW_SAMPLE_ALLOW_RATE", "0.01"))
        llm_deny_threshold = float(os.getenv("GUARD_LLM_REVIEW_DENY_CONFIDENCE", "0.92"))
        llm_approval_threshold = float(os.getenv("GUARD_LLM_REVIEW_APPROVAL_CONFIDENCE", "0.65"))
        for name, value in (
            ("GUARD_LLM_REVIEW_SAMPLE_ALLOW_RATE", llm_sample_allow_rate),
            ("GUARD_LLM_REVIEW_DENY_CONFIDENCE", llm_deny_threshold),
            ("GUARD_LLM_REVIEW_APPROVAL_CONFIDENCE", llm_approval_threshold),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        llm_enabled = _env_bool("GUARD_LLM_ENABLED", False)
        llm_model = os.getenv("GUARD_LLM_MODEL") or None
        llm_base_url = os.getenv("GUARD_LLM_BASE_URL") or None
        llm_api_key_env = os.getenv("GUARD_LLM_API_KEY_ENV", "GUARD_LLM_API_KEY").strip()
        if llm_enabled and not llm_api_key_env:
            raise ValueError("GUARD_LLM_API_KEY_ENV must name a non-empty environment variable")
        if llm_enabled and (not llm_model or not llm_base_url):
            raise ValueError("GUARD_LLM_MODEL and GUARD_LLM_BASE_URL are required when GUARD_LLM_ENABLED=true")
        if not llm_enabled and llm_review_mode != "disabled":
            raise ValueError("GUARD_LLM_ENABLED must be true when GUARD_LLM_REVIEW_MODE is not disabled")
        if not llm_enabled and task_policy_synthesizer == "hybrid":
            raise ValueError("GUARD_LLM_ENABLED must be true when GUARD_TASK_POLICY_SYNTHESIZER=hybrid")
        if llm_base_url:
            from urllib.parse import urlsplit

            parsed_url = urlsplit(llm_base_url)
            if parsed_url.scheme not in {"https", "http"} or not parsed_url.hostname:
                raise ValueError("GUARD_LLM_BASE_URL must be an absolute HTTP(S) URL")
            if parsed_url.scheme == "http" and parsed_url.hostname not in {"127.0.0.1", "::1", "localhost"}:
                raise ValueError("GUARD_LLM_BASE_URL must use HTTPS unless it targets loopback")
        return cls(
            host=host,
            port=port,
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
            llm_enabled=llm_enabled,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_base_url=llm_base_url,
            llm_api_key_env=llm_api_key_env,
            llm_request_timeout_ms=max(500, min(int(os.getenv("GUARD_LLM_REQUEST_TIMEOUT_MS", "8000")), 120_000)),
            llm_connect_timeout_ms=max(100, min(int(os.getenv("GUARD_LLM_CONNECT_TIMEOUT_MS", "1000")), 30_000)),
            llm_max_input_bytes=max(4096, min(int(os.getenv("GUARD_LLM_MAX_INPUT_BYTES", "65536")), 1_048_576)),
            llm_max_output_bytes=max(1024, min(int(os.getenv("GUARD_LLM_MAX_OUTPUT_BYTES", "16384")), 1_048_576)),
            llm_max_output_tokens=max(128, min(int(os.getenv("GUARD_LLM_MAX_OUTPUT_TOKENS", "1500")), 100_000)),
            llm_max_concurrency=max(1, min(int(os.getenv("GUARD_LLM_MAX_CONCURRENCY", "2")), 32)),
            llm_queue_capacity=max(1, min(int(os.getenv("GUARD_LLM_QUEUE_CAPACITY", "256")), 10_000)),
            llm_cache_ttl_minutes=max(1, min(int(os.getenv("GUARD_LLM_CACHE_TTL_MINUTES", "60")), 10_080)),
            llm_circuit_breaker_failures=max(1, min(int(os.getenv("GUARD_LLM_CIRCUIT_BREAKER_FAILURES", "5")), 100)),
            llm_circuit_breaker_cooldown_seconds=max(
                1, min(int(os.getenv("GUARD_LLM_CIRCUIT_BREAKER_COOLDOWN_SECONDS", "60")), 3600),
            ),
            llm_review_mode=llm_review_mode,
            llm_review_sample_allow_rate=llm_sample_allow_rate,
            llm_review_deny_confidence_threshold=llm_deny_threshold,
            llm_review_approval_confidence_threshold=llm_approval_threshold,
            task_policy_synthesizer=task_policy_synthesizer,
            task_policy_model_timeout_ms=max(
                500, min(int(os.getenv("GUARD_TASK_POLICY_MODEL_TIMEOUT_MS", "8000")), 120_000),
            ),
        )

    @property
    def db_path(self) -> Path:
        return self.state_dir / "guardagent.sqlite3"

    @property
    def token_path(self) -> Path:
        return self.state_dir / "guardd.token"

    @property
    def security_override_token_path(self) -> Path:
        return self.state_dir / "guardd.security-override.token"

    @property
    def emergency_log_path(self) -> Path:
        return self.state_dir / "emergency.jsonl"

    @property
    def hmac_key_path(self) -> Path:
        return self.state_dir / "guardd.hmac"
