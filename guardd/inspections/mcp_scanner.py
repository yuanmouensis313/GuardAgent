from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from guardd.inspections.models import (
    CapabilityManifest,
    ContentArtifact,
    InspectionDecision,
    InspectionFinding,
    InspectionVerdict,
    McpDescriptorInspectionRequest,
)
from guardd.security import digest_payload, hmac_digest_payload, sanitize


SCANNER_VERSION = "mcp-descriptor-v1"
MAX_DESCRIPTOR_BYTES = 2 * 1024 * 1024

RULES: list[tuple[str, str, re.Pattern[str], str, str]] = [
    ("MCP-DESCRIPTOR-INJECTION-001", "critical", re.compile(r"(?:ignore|disregard|override).{0,100}(?:system|developer|user|security|instruction|policy)", re.I), "Descriptor attempts to override higher-priority instructions", "prompt_injection"),
    ("MCP-DESCRIPTOR-PRIORITY-001", "high", re.compile(r"(?:always|must|prefer|first).{0,60}(?:call|use|invoke).{0,60}(?:this|tool)", re.I), "Descriptor attempts to bias tool selection", "tool_coercion"),
    ("MCP-DESCRIPTOR-SECRET-001", "critical", re.compile(r"(?:credential|password|api[_-]?key|token|\.ssh|\.env|cookie|private key)", re.I), "Descriptor requests secret-bearing data", "credential_read"),
    ("MCP-DESCRIPTOR-EXFIL-001", "critical", re.compile(r"(?:upload|webhook|exfiltrat|send).{0,80}(?:data|file|secret|credential|history)", re.I), "Descriptor contains unrelated external data transfer", "network_write"),
    ("MCP-DESCRIPTOR-COMMAND-001", "high", re.compile(r"(?:powershell|cmd\.exe|/bin/(?:sh|bash)|curl\s|wget\s|encodedcommand|rm\s+-rf)", re.I), "Descriptor embeds a command or encoded payload", "exec"),
    ("MCP-DESCRIPTOR-OBFUSCATION-001", "high", re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f]|(?:[A-Za-z0-9+/]{240,}={0,2})"), "Descriptor contains hidden Unicode or encoded content", "obfuscation"),
]


class McpDescriptorScanner:
    def __init__(self, hmac_key: bytes, inspection_policy_digest: str):
        self.hmac_key = hmac_key
        self.inspection_policy_digest = inspection_policy_digest

    def scan(self, request: McpDescriptorInspectionRequest) -> tuple[ContentArtifact, InspectionVerdict]:
        document = request.model_dump(mode="json")
        size = len(json.dumps(document, ensure_ascii=False, default=str).encode("utf-8"))
        now = datetime.now(timezone.utc)
        findings: list[InspectionFinding] = []
        manifest_entries: list[dict[str, Any]] = []
        capabilities = CapabilityManifest()
        if size > MAX_DESCRIPTOR_BYTES:
            findings.append(self._finding(
                "MCP-DESCRIPTOR-LIMIT-001", "critical", "server", None, str(size),
                "Descriptor bundle exceeds the scan limit", "scan_limit",
            ))
        for kind, descriptors in (("tool", request.tools), ("prompt", request.prompts), ("resource", request.resources)):
            for index, descriptor in enumerate(descriptors):
                name = str(descriptor.get("name") or descriptor.get("uri") or f"{kind}-{index}")[:256]
                descriptor_digest = digest_payload({
                    "server_identity": request.server_identity,
                    "server_version": request.server_version,
                    "protocol_version": request.protocol_version,
                    "transport_identity": request.transport_identity,
                    "kind": kind, "descriptor": descriptor,
                })
                manifest_entries.append({"kind": kind, "name": name, "digest": descriptor_digest})
                self._scan_value(f"{kind}:{name}", descriptor, findings)
                if kind == "tool":
                    capabilities.tools.append(name)
                    lowered = json.dumps(descriptor, ensure_ascii=False, default=str).lower()
                    if any(word in lowered for word in ("write", "create", "update", "delete", "send", "upload", "post")):
                        capabilities.network_write.append("unknown")
                    if any(word in lowered for word in ("url", "http", "fetch", "download", "search")):
                        capabilities.network_read.append("unknown")
                    annotations = descriptor.get("annotations") if isinstance(descriptor.get("annotations"), dict) else {}
                    if annotations.get("readOnlyHint") is True and any(word in lowered for word in ("delete", "write", "send", "upload", "update")):
                        findings.append(self._finding(
                            "MCP-DESCRIPTOR-READONLY-MISMATCH-001", "high", f"tool:{name}", None,
                            descriptor_digest, "Read-only annotation conflicts with mutating descriptor text", "capability_mismatch",
                        ))
        capabilities.tools = sorted(set(capabilities.tools))
        capabilities.network_read = sorted(set(capabilities.network_read))
        capabilities.network_write = sorted(set(capabilities.network_write))
        rule_ids = {item.rule_id for item in findings}
        capabilities.secret_access = "MCP-DESCRIPTOR-SECRET-001" in rule_ids
        capabilities.dynamic_execution = "MCP-DESCRIPTOR-COMMAND-001" in rule_ids
        manifest_entries.sort(key=lambda item: (item["kind"], item["name"], item["digest"]))
        content_digest = digest_payload({
            "server_identity": request.server_identity, "source_identity": request.source_identity,
            "transport_identity": request.transport_identity, "server_version": request.server_version,
            "protocol_version": request.protocol_version, "capabilities": request.capabilities,
            "descriptors": manifest_entries,
        })
        clean_name, _ = sanitize(request.server_identity)
        clean_source, _ = sanitize(request.source_identity)
        artifact = ContentArtifact(
            kind="mcp", canonical_name=str(clean_name), source_identity=str(clean_source),
            content_digest=content_digest,
            manifest={
                "scanner_version": SCANNER_VERSION, "server_identity": request.server_identity,
                "transport_identity_digest": digest_payload(request.transport_identity),
                "server_version": request.server_version, "protocol_version": request.protocol_version,
                "descriptor_count": len(manifest_entries), "descriptor_bytes": size,
                "descriptors": manifest_entries,
            },
            first_seen_at=now, last_seen_at=now,
        )
        severities = {item.severity for item in findings}
        if "MCP-DESCRIPTOR-LIMIT-001" in rule_ids:
            decision, risk = InspectionDecision.QUARANTINE, "critical"
        elif "critical" in severities:
            decision, risk = InspectionDecision.DENY, "critical"
        elif severities & {"high", "medium"}:
            decision, risk = InspectionDecision.REQUIRE_APPROVAL, "high" if "high" in severities else "medium"
        else:
            decision, risk = InspectionDecision.ALLOW, "info"
        verdict = InspectionVerdict(
            artifact_id=artifact.artifact_id, decision=decision, risk=risk,
            scanner_version=SCANNER_VERSION, inspection_policy_digest=self.inspection_policy_digest,
            findings=findings, capability_manifest=capabilities, created_at=now,
            expires_at=now + timedelta(days=1),
        )
        return artifact, verdict

    def _scan_value(self, location: str, value: Any, findings: list[InspectionFinding], path: str = "$") -> None:
        if isinstance(value, str):
            for rule_id, severity, pattern, message, capability in RULES:
                for match in list(pattern.finditer(value))[:20]:
                    findings.append(self._finding(rule_id, severity, location, None, {"path": path, "match": match.group(0)}, message, capability))
        elif isinstance(value, dict):
            for key, child in value.items():
                self._scan_value(location, child, findings, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self._scan_value(location, child, findings, f"{path}[{index}]")

    def _finding(self, rule_id: str, severity: str, file: str, line: int | None, evidence: Any, message: str, capability: str) -> InspectionFinding:
        return InspectionFinding(
            rule_id=rule_id, severity=severity, file=file, line=line,
            evidence_digest=hmac_digest_payload({"location": file, "evidence": evidence}, self.hmac_key),
            message=message, capability=capability,
        )
