from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from guardd.models.events import GuardEvent


class BootstrapRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str


class SessionRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    code: str = Field(min_length=32, max_length=512)


class OperatorRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str


class PolicyCandidateRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    policy: str = Field(min_length=1)


class PolicySimulationRequest(PolicyCandidateRequest):
    event: GuardEvent


class PolicyRegressionRequest(PolicyCandidateRequest):
    session_key: str | None = None


class PolicyPublishRequest(PolicyCandidateRequest):
    expected_digest: str
    comment: str = Field(default="", max_length=500)
    confirmation: str | None = None


class PolicyRestoreRequest(OperatorRequest):
    expected_digest: str
    confirmation: str | None = None


class ReplayRequest(OperatorRequest):
    policy: str | None = None


class TaskPolicyDecisionRequest(OperatorRequest):
    candidate_digest: str
    expected_active_revision: int | None = None


class UiError(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class UiErrorEnvelope(BaseModel):
    error: UiError


class BootstrapResponse(BaseModel):
    code: str
    expires_at: str
    server_time: str


class UiSessionResponse(BaseModel):
    operator: str
    csrf_token: str
    created_at: str
    last_seen: str
    expires_at: str
    server_time: str


class StatusResponse(BaseModel):
    status: str
    server_time: str


class ItemResponse(BaseModel):
    item: Any
    server_time: str


class ItemsResponse(BaseModel):
    items: list[Any]
    server_time: str


class PageResponse(ItemsResponse):
    next_cursor: str | int | None = None


class OverviewResponse(BaseModel):
    status: dict[str, Any]
    metrics: dict[str, Any]
    pending_approvals: list[dict[str, Any]]
    recent_incidents: list[dict[str, Any]]
    recent_high_risk: list[dict[str, Any]]
    range: str
    server_time: str


class SettingsResponse(BaseModel):
    item: dict[str, Any]
    sources: dict[str, str]
    restart_required: bool
    server_time: str


class FlexibleResponse(BaseModel):
    """Schema for SSE-adjacent or aggregate responses with endpoint-specific fields."""

    model_config = ConfigDict(extra="allow")
    server_time: str
