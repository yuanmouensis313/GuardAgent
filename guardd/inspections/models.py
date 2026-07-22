from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class InspectionDecision(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    STALE = "STALE"


class InspectionFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    file: str
    line: int | None = None
    evidence_digest: str
    message: str
    capability: str | None = None


class CapabilityManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(default_factory=list)
    file_read_patterns: list[str] = Field(default_factory=list)
    file_write_patterns: list[str] = Field(default_factory=list)
    network_read: list[str] = Field(default_factory=list)
    network_write: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    dynamic_execution: bool = False
    secret_access: bool = False
    persistence: bool = False
    subagent: bool = False
    unknown: list[str] = Field(default_factory=list)


class ContentArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: UUID = Field(default_factory=uuid4)
    kind: Literal["skill", "mcp"]
    canonical_name: str
    source_identity: str
    content_digest: str
    manifest: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime


class InspectionVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict_id: UUID = Field(default_factory=uuid4)
    artifact_id: UUID
    status: Literal["valid", "stale"] = "valid"
    decision: InspectionDecision
    risk: Literal["info", "low", "medium", "high", "critical"]
    scanner_version: str
    inspection_policy_digest: str
    findings: list[InspectionFinding]
    capability_manifest: CapabilityManifest
    created_at: datetime
    expires_at: datetime | None = None


class SkillInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    source_path: str
    canonical_name: str
    source_identity: str = "local-install"
    expected_content_digest: str | None = None
    builtin_findings: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)


class McpDescriptorInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    server_identity: str = Field(min_length=1, max_length=512)
    source_identity: str = Field(default="local-mcp-proxy", max_length=512)
    transport_identity: str = Field(max_length=512)
    server_version: str | None = Field(default=None, max_length=256)
    protocol_version: str | None = Field(default=None, max_length=64)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    tools: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    prompts: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    resources: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


class InspectionConfirmationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    operator: str = "local-operator"
    decision: Literal["approve", "deny"]
    scope: Literal["allow-once", "allow-for-session", "allow-this-digest"] = "allow-this-digest"
    session_key: str | None = None
