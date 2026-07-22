from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from guardd.audit.store import AuditStore
from guardd.inspections.mcp_scanner import SCANNER_VERSION as MCP_SCANNER_VERSION, McpDescriptorScanner
from guardd.inspections.models import (
    InspectionConfirmationRequest, InspectionDecision, McpDescriptorInspectionRequest, SkillInspectionRequest,
)
from guardd.inspections.skill_scanner import SCANNER_VERSION, SkillScanError, SkillScanner


class InspectionError(ValueError):
    pass


class InspectionManager:
    def __init__(self, store: AuditStore, hmac_key: bytes, inspection_policy_digest: str):
        self.store = store
        self.inspection_policy_digest = inspection_policy_digest
        self.skill_scanner = SkillScanner(hmac_key, inspection_policy_digest)
        self.mcp_scanner = McpDescriptorScanner(hmac_key, inspection_policy_digest)

    def update_policy_digest(self, digest: str) -> None:
        self.inspection_policy_digest = digest
        self.skill_scanner.inspection_policy_digest = digest
        self.mcp_scanner.inspection_policy_digest = digest

    def inspect_skill(self, request: SkillInspectionRequest) -> dict[str, Any]:
        try:
            artifact, verdict = self.skill_scanner.scan(
                Path(request.source_path), request.canonical_name,
                request.source_identity, request.builtin_findings,
            )
        except (OSError, SkillScanError, ValueError) as exc:
            raise InspectionError(str(exc)) from exc
        if request.expected_content_digest and request.expected_content_digest != artifact.content_digest:
            raise InspectionError("skill content digest changed before inspection completed")
        cached = self.store.get_cached_inspection(
            "skill", artifact.source_identity, artifact.content_digest,
            SCANNER_VERSION, self.inspection_policy_digest,
        )
        if cached is not None:
            detail = self.store.get_inspection(artifact.content_digest)
            if detail is not None:
                detail["cache_hit"] = True
                detail["effective_decision"] = self.effective_decision(artifact.content_digest)
                return detail
        self.store.record_content_inspection(artifact, verdict)
        detail = self.store.get_inspection(artifact.content_digest)
        if detail is None:
            raise InspectionError("inspection persistence failed")
        detail["cache_hit"] = False
        detail["effective_decision"] = self.effective_decision(artifact.content_digest)
        return detail

    def inspect_mcp(self, request: McpDescriptorInspectionRequest) -> dict[str, Any]:
        try:
            artifact, verdict = self.mcp_scanner.scan(request)
        except (OSError, ValueError) as exc:
            raise InspectionError(str(exc)) from exc
        cached = self.store.get_cached_inspection(
            "mcp", artifact.source_identity, artifact.content_digest,
            MCP_SCANNER_VERSION, self.inspection_policy_digest,
        )
        if cached is None:
            self.store.record_content_inspection(artifact, verdict)
        detail = self.store.get_inspection(artifact.content_digest)
        if detail is None:
            raise InspectionError("MCP inspection persistence failed")
        detail["cache_hit"] = cached is not None
        detail["effective_decision"] = self.effective_decision(artifact.content_digest)
        return detail

    def get(self, content_digest: str) -> dict[str, Any]:
        detail = self.store.get_inspection(content_digest)
        if detail is None:
            raise InspectionError("inspection not found")
        return detail

    def confirm(self, content_digest: str, request: InspectionConfirmationRequest) -> dict[str, Any]:
        detail = self.get(content_digest)
        verdict = detail.get("verdict") or {}
        decision = str(verdict.get("decision", "STALE"))
        if request.decision == "approve" and decision in {"DENY", "QUARANTINE", "STALE"}:
            raise InspectionError("a static deny, quarantine, or stale verdict cannot be approved")
        if request.scope == "allow-for-session" and not request.session_key:
            raise InspectionError("allow-for-session requires session_key")
        self.store.record_content_confirmation(
            str(uuid4()), str(verdict["verdict_id"]), request.operator,
            request.decision, request.scope, request.session_key,
        )
        return self.get(content_digest)

    def invalidate(self, content_digest: str) -> dict[str, Any]:
        if self.store.invalidate_inspection(content_digest) == 0:
            raise InspectionError("inspection not found or already stale")
        return self.get(content_digest)

    def effective_decision(self, content_digest: str, session_key: str | None = None) -> str:
        detail = self.get(content_digest)
        verdict = detail.get("verdict") or {}
        if verdict.get("status") != "valid":
            return InspectionDecision.STALE.value
        expires_at = verdict.get("expires_at")
        if expires_at and datetime.fromisoformat(str(expires_at)) <= datetime.now(timezone.utc):
            return InspectionDecision.STALE.value
        decision = str(verdict.get("decision", "STALE"))
        if decision in {"DENY", "QUARANTINE", "STALE"}:
            return decision
        for confirmation in detail.get("confirmations", []):
            if confirmation["decision"] == "deny":
                return InspectionDecision.DENY.value
            if confirmation["decision"] != "approve":
                continue
            if confirmation["scope"] == "allow-this-digest":
                return InspectionDecision.ALLOW.value
            if confirmation["scope"] == "allow-for-session" and confirmation.get("session_key") == session_key:
                return InspectionDecision.ALLOW.value
        return decision
