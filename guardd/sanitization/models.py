from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SanitizationTransformation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    json_path: str = Field(max_length=1024)
    classification: str = Field(max_length=128)
    length: int = Field(ge=0)
    source: str = Field(max_length=128)
    proposed_action: Literal["preserve", "redact", "drop", "late_bind", "block", "require_approval"]
    ref: str = Field(max_length=128)


class SanitizationEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    sanitizer_event_id: str
    direction: Literal["inbound", "outbound"]
    session_key: str
    tool_name: str
    tool_call_id: str | None = None
    classifications: list[str] = Field(default_factory=list, max_length=100)
    transformations: list[SanitizationTransformation] = Field(default_factory=list, max_length=1000)
    original_size: int = Field(ge=0)
    result_size: int = Field(ge=0)
    truncated: bool = False
    blocked: bool = False
    pattern_digest: str | None = None
    content_digest: str | None = None
