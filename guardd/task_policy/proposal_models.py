from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TrustedOrigin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field(max_length=128)
    sender_digest: str | None = None
    is_local_operator: bool = False


class TrustedPathAlias(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str = Field(pattern=r"^PATH_\d+$")
    access: Literal["read", "write"]


class TrustedDomainAlias(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str = Field(pattern=r"^DOMAIN_\d+$")
    direction: Literal["read", "write"]


class TrustedTaskContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    session_key: str
    agent_id: str
    parent_policy_digest: str | None = None
    sanitized_user_prompt: str = Field(min_length=1, max_length=100_000)
    origin: TrustedOrigin
    path_aliases: list[TrustedPathAlias] = Field(default_factory=list, max_length=200)
    domain_aliases: list[TrustedDomainAlias] = Field(default_factory=list, max_length=200)
    registered_tools: list[str] = Field(default_factory=list, max_length=200)
    base_constraints_digest: str
    active_task_summary: str | None = Field(default=None, max_length=512)


class ProposalTools(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required: list[str] = Field(default_factory=list, max_length=100)
    optional: list[str] = Field(default_factory=list, max_length=100)
    deny: list[str] = Field(default_factory=list, max_length=100)


class ProposalFiles(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read: list[str] = Field(default_factory=list, max_length=100)
    write: list[str] = Field(default_factory=list, max_length=100)


class ProposalNetwork(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read: list[str] = Field(default_factory=list, max_length=100)
    write: list[str] = Field(default_factory=list, max_length=100)


class ProposalCommands(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_prefixes: list[str] = Field(default_factory=list, max_length=100)
    approval_categories: list[str] = Field(default_factory=list, max_length=100)


class ProposalLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_tool_calls: int = Field(default=30, ge=1, le=10_000)
    max_external_writes: int = Field(default=0, ge=0, le=10_000)
    max_files_changed: int = Field(default=0, ge=0, le=100_000)
    ttl_minutes: int = Field(default=120, ge=1, le=1440)


class ProposalEvidenceSpan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: int = Field(ge=0)
    end: int = Field(gt=0)


class ProposalEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_span: ProposalEvidenceSpan
    supports: str = Field(pattern=r"^\$\.[A-Za-z_][A-Za-z0-9_.\[\]]*$", max_length=512)


class TaskPolicyProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    objective_summary: str = Field(min_length=1, max_length=512)
    tools: ProposalTools = Field(default_factory=ProposalTools)
    files: ProposalFiles = Field(default_factory=ProposalFiles)
    network: ProposalNetwork = Field(default_factory=ProposalNetwork)
    commands: ProposalCommands = Field(default_factory=ProposalCommands)
    limits: ProposalLimits = Field(default_factory=ProposalLimits)
    uncertainties: list[str] = Field(default_factory=list, max_length=100)
    evidence: list[ProposalEvidence] = Field(default_factory=list, max_length=200)


class CompiledTaskPolicyProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_digest: str
    proposal_digest: str
    accepted_fields: list[str] = Field(default_factory=list)
    rejected_fields: list[dict[str, str]] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
