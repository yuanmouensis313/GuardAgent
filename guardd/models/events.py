from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

class Origin(BaseModel):
    channel: str = "local"
    channel_id: str | None = None
    sender_id: str | None = None
    is_local_operator: bool = False


class ToolDescriptor(BaseModel):
    name: str
    kind: str = "unknown"
    input_kind: str | None = None


class TraceContext(BaseModel):
    trace_id: str | None = None
    span_id: str | None = None


class ContentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["native", "skill", "mcp"] = "native"
    name: str
    digest: str | None = None
    artifact_digest: str | None = None
    server_identity: str | None = None


class GuardEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0", "1.1"] = "1.0"
    event_id: UUID = Field(default_factory=uuid4)
    event_type: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: Literal["openclaw", "guardctl", "test"] = "openclaw"
    gateway_id: str = "local-gateway"
    agent_id: str
    session_key: str
    parent_session_key: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    tool_call_id: str | None = None
    origin: Origin = Field(default_factory=Origin)
    tool: ToolDescriptor | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    derived: dict[str, Any] = Field(default_factory=dict)
    data_classification: list[str] = Field(default_factory=list)
    trace: TraceContext = Field(default_factory=TraceContext)
    content_identity: ContentIdentity | None = None

    @field_validator("occurred_at")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include timezone")
        return value


class ToolResultEvent(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    event_id: UUID
    tool_call_id: str | None = None
    success: bool
    exit_code: int | None = None
    duration_ms: float | None = None
    output: Any = None
    error: str | None = None


class SessionEvent(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    event: GuardEvent

class DecisionRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    event: GuardEvent
