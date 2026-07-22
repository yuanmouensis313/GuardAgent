from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardd.models.events import Origin


class TaskPolicyStatus(StrEnum):
    CANDIDATE = "candidate"
    REVISION_CANDIDATE = "revision_candidate"
    ACTIVE = "active"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    CLOSED = "closed"


class TaskObjective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=512)
    source_digest: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")


class TaskToolRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(default_factory=list, max_length=100)
    deny: list[str] = Field(default_factory=list, max_length=100)


class TaskFileRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read: list[str] = Field(default_factory=list, max_length=100)
    write: list[str] = Field(default_factory=list, max_length=100)
    deny: list[str] = Field(default_factory=list, max_length=100)


class TaskNetworkRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read: list[str] = Field(default_factory=list, max_length=100)
    write: list[str] = Field(default_factory=list, max_length=100)
    deny: list[str] = Field(default_factory=list, max_length=100)


class TaskCommandRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_prefixes: list[str] = Field(default_factory=list, max_length=100)
    deny_prefixes: list[str] = Field(default_factory=list, max_length=100)
    approval_categories: list[str] = Field(default_factory=list, max_length=100)


class TaskSkillRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_digests: list[str] = Field(default_factory=list, max_length=100)
    deny_names: list[str] = Field(default_factory=list, max_length=100)


class TaskMcpRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_tools: list[str] = Field(default_factory=list, max_length=100)
    allow_descriptor_digests: list[str] = Field(default_factory=list, max_length=100)


class TaskLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_tool_calls: int = Field(default=30, ge=1, le=10_000)
    max_external_writes: int = Field(default=0, ge=0, le=10_000)
    max_files_changed: int = Field(default=10, ge=0, le=100_000)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must include timezone")
        return value


class TaskProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generator: Literal["deterministic", "hybrid"] = "deterministic"
    generator_version: str = "1"
    model: str | None = None
    prompt_digest: str | None = None
    origin_channel: str | None = None
    origin_sender_digest: str | None = None
    origin_is_local_operator: bool = False


class TaskPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    task_policy_id: UUID = Field(default_factory=uuid4)
    session_key: str = Field(min_length=1, max_length=512)
    agent_id: str = Field(min_length=1, max_length=256)
    parent_session_key: str | None = Field(default=None, max_length=512)
    parent_policy_digest: str | None = None
    revision: int = Field(ge=1)
    status: TaskPolicyStatus = TaskPolicyStatus.CANDIDATE
    policy_digest: str = ""
    base_policy_digest: str
    objective: TaskObjective
    tools: TaskToolRules = Field(default_factory=TaskToolRules)
    files: TaskFileRules = Field(default_factory=TaskFileRules)
    network: TaskNetworkRules = Field(default_factory=TaskNetworkRules)
    commands: TaskCommandRules = Field(default_factory=TaskCommandRules)
    skills: TaskSkillRules = Field(default_factory=TaskSkillRules)
    mcp: TaskMcpRules = Field(default_factory=TaskMcpRules)
    limits: TaskLimits
    provenance: TaskProvenance = Field(default_factory=TaskProvenance)
    created_at: datetime
    activated_at: datetime | None = None
    closed_at: datetime | None = None

    @field_validator("created_at", "activated_at", "closed_at")
    @classmethod
    def timestamps_require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("task policy timestamps must include timezone")
        return value

    def digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload.pop("policy_digest", None)
        payload.pop("status", None)
        payload.pop("activated_at", None)
        payload.pop("closed_at", None)
        return payload


class TaskPolicyCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    session_key: str
    agent_id: str
    parent_session_key: str | None = None
    prompt: str = Field(min_length=1, max_length=100_000)
    origin: Origin = Field(default_factory=Origin)


class TaskPolicyActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    candidate_digest: str
    expected_active_revision: int | None = None
    operator: str = "local-operator"


class TaskPolicyRejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    candidate_digest: str
    operator: str = "local-operator"


class TaskPolicyCloseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    operator: str = "local-operator"


class TaskPolicyContentRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    kind: Literal["skill", "mcp"]
    name: str
    content_digest: str
    artifact_digest: str | None = None
    expected_active_revision: int
    operator: str = "local-operator"
