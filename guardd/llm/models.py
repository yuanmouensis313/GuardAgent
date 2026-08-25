from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReviewSubject(StrEnum):
    TOOL_CALL = "tool_call"
    MESSAGE_SEND = "message_send"
    SKILL_INSPECTION = "skill_inspection"
    MCP_DESCRIPTOR = "mcp_descriptor"


class ReviewMode(StrEnum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    ADVISORY = "advisory"
    ENFORCE_TIGHTEN = "enforce_tighten"


class ReviewTrigger(StrEnum):
    SKIP = "SKIP"
    SAMPLE_SHADOW = "SAMPLE_SHADOW"
    REVIEW_OPTIONAL = "REVIEW_OPTIONAL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class ReviewVerdict(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    UNCERTAIN = "UNCERTAIN"


class ReviewThreat(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"
    SCOPE_ESCAPE = "scope_escape"
    SECURITY_BYPASS = "security_bypass"
    DESTRUCTIVE_ACTION = "destructive_action"
    DECEPTION = "deception"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNRELATED_ACTION = "unrelated_action"


class IntentAlignment(StrEnum):
    ALIGNED = "aligned"
    PARTIALLY_ALIGNED = "partially_aligned"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class ReviewJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    INVALID = "invalid"
    CANCELLED = "cancelled"


class ReviewReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: UUID
    fingerprint: str
    status: ReviewJobStatus
    cache_hit: bool = False


class ReviewObjective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(default="No active task objective", min_length=1, max_length=512)
    task_policy_digest: str | None = None


class ReviewCommandSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executable: str = Field(default="", max_length=128)
    argv_categories: list[str] = Field(default_factory=list, max_length=50)
    dynamic_eval: bool = False
    parse_failed: bool = False
    shell_features: list[str] = Field(default_factory=list, max_length=50)


class ReviewTargetSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    classification: str = Field(max_length=128)
    access: str | None = Field(default=None, max_length=64)
    direction: str | None = Field(default=None, max_length=64)


class ReviewEventSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(max_length=128)
    tool_name: str = Field(max_length=256)
    tool_kind: str = Field(max_length=128)
    normalized_actions: list[str] = Field(default_factory=list, max_length=50)
    command_summaries: list[ReviewCommandSummary] = Field(default_factory=list, max_length=10)
    path_targets: list[ReviewTargetSummary] = Field(default_factory=list, max_length=100)
    network_targets: list[ReviewTargetSummary] = Field(default_factory=list, max_length=100)
    data_classification: list[str] = Field(default_factory=list, max_length=100)


class ReviewLocalSignals(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_decision: str
    risk: str
    rule_ids: list[str] = Field(default_factory=list, max_length=200)
    task_verdict: str | None = None
    correlation_rule_ids: list[str] = Field(default_factory=list, max_length=100)
    content_verdict: str | None = None


class MemoryActionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(max_length=64)
    target_class: str = Field(max_length=128)
    result: str = Field(max_length=64)
    age_seconds: int = Field(ge=0)


class MemorySensitiveAccess(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: str = Field(max_length=128)
    target_digest: str
    age_seconds: int = Field(ge=0)


class SafetyMemorySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    session_key: str
    snapshot_at: datetime
    active_task_policy_digest: str | None = None
    counters: dict[str, int] = Field(default_factory=dict)
    recent_actions: list[MemoryActionSummary] = Field(default_factory=list, max_length=20)
    sensitive_access: list[MemorySensitiveAccess] = Field(default_factory=list, max_length=20)
    denied_patterns: list[str] = Field(default_factory=list, max_length=50)
    risk_score: int = Field(default=0, ge=0, le=10_000)

    @field_validator("snapshot_at")
    @classmethod
    def snapshot_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("snapshot_at must include timezone")
        return value


class SafetyReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    subject: ReviewSubject
    objective: ReviewObjective
    event: ReviewEventSummary
    local_signals: ReviewLocalSignals
    memory: SafetyMemorySnapshot
    trust_labels: dict[str, str] = Field(default_factory=dict)


class ReviewEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=64)
    path: str = Field(pattern=r"^\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*$", max_length=512)
    claim: str = Field(min_length=1, max_length=512)


class ReviewConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_paths: list[str] = Field(default_factory=list, max_length=100)
    allowed_domains: list[str] = Field(default_factory=list, max_length=100)
    allowed_tools: list[str] = Field(default_factory=list, max_length=100)
    max_external_writes: int | None = Field(default=None, ge=0, le=10_000)
    max_files_changed: int | None = Field(default=None, ge=0, le=100_000)


class SafetyReviewResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    verdict: ReviewVerdict
    risk: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    threats: list[ReviewThreat] = Field(default_factory=list, max_length=20)
    intent_alignment: IntentAlignment
    evidence: list[ReviewEvidence] = Field(default_factory=list, max_length=50)
    recommended_action: ReviewVerdict
    constraints: ReviewConstraints = Field(default_factory=ReviewConstraints)
    summary: str = Field(min_length=1, max_length=1000)


class ValidationOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: SafetyReviewResult
    valid: bool
    issues: list[str] = Field(default_factory=list)
    output_secret_echo: bool = False


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(default_factory=uuid4)
    idempotency_key: str
    system_template: str
    input_document: dict[str, Any]
    model: str
    response_schema_name: str
    response_schema_version: str
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_output_tokens: int = Field(default=1500, ge=1, le=100_000)
    tools_allowed: bool = False


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    provider: str
    model: str
    payload: dict[str, Any]
    raw_response_digest: str
    token_input: int | None = Field(default=None, ge=0)
    token_output: int | None = Field(default=None, ge=0)
    latency_ms: int = Field(ge=0)
    finish_reason: str | None = Field(default=None, max_length=128)
