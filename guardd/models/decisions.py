from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DecisionKind(StrEnum):
    OBSERVE = "OBSERVE"
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class RiskLevel(IntEnum):
    info = 0
    low = 1
    medium = 2
    high = 3
    critical = 4


DECISION_ORDER = {
    DecisionKind.OBSERVE: 0,
    DecisionKind.ALLOW: 1,
    DecisionKind.REQUIRE_APPROVAL: 2,
    DecisionKind.DENY: 3,
}


class Decision(BaseModel):
    decision_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    decision: DecisionKind
    would_decide: DecisionKind | None = None
    risk: str
    rule_ids: list[str] = Field(default_factory=list)
    reason: str
    effective_mode: str
    expires_at: datetime | None = None
    parameter_digest: str
    sanitized_params: dict[str, Any] = Field(default_factory=dict)
    rewritten_params: dict[str, Any] | None = None
    remediation: str | None = None
    approval_id: UUID | None = None
