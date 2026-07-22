from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from guardd.inspections.models import (
    CapabilityManifest,
    ContentArtifact,
    InspectionDecision,
    InspectionFinding,
    InspectionVerdict,
)
from guardd.security import digest_payload, hmac_digest_payload, sanitize


SCANNER_VERSION = "skill-static-v1"
MAX_FILES = 500
MAX_TOTAL_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_DEPTH = 12

RULES: list[tuple[str, str, re.Pattern[str], str, str | None]] = [
    ("SKILL-INJECTION-001", "critical", re.compile(r"(?:ignore|disregard|override).{0,80}(?:system|developer|user|security|policy|instruction)", re.I), "Attempts to override higher-priority instructions", "prompt_injection"),
    ("SKILL-STEALTH-001", "high", re.compile(r"(?:hide|conceal|do not tell|don't tell|delete).{0,80}(?:user|log|audit|history|evidence)", re.I), "Requests concealed behavior or audit deletion", "stealth"),
    ("SKILL-SECRET-READ-001", "critical", re.compile(r"(?:\.ssh|id_rsa|id_ed25519|\.env|credentials|keychain|login data|cookies|api[_-]?key|password)", re.I), "References credential or secret-bearing data", "credential_read"),
    ("SKILL-NETWORK-WRITE-001", "high", re.compile(r"(?:webhook|upload|exfiltrat|requests\.post|fetch\s*\(|curl\s+.*(?:-d|--data)|send[_-]?(?:mail|message))", re.I), "Contains network write or messaging behavior", "network_write"),
    ("SKILL-DYNAMIC-EXEC-001", "critical", re.compile(r"(?:\beval\s*\(|\bexec\s*\(|encodedcommand|frombase64string|base64\s+-d|downloadstring|invoke-expression)", re.I), "Contains dynamic or encoded execution", "dynamic_execution"),
    ("SKILL-SHELL-001", "high", re.compile(r"(?:subprocess\.|os\.system|child_process|powershell|cmd\.exe|/bin/(?:sh|bash))", re.I), "Invokes a shell or process runtime", "exec"),
    ("SKILL-SELF-PROTECT-001", "critical", re.compile(r"(?:guardagent|guardd|openclaw).{0,80}(?:config|policy|disable|bypass|uninstall|delete)", re.I), "Attempts to modify security configuration", "security_self_modify"),
    ("SKILL-PERSISTENCE-001", "critical", re.compile(r"(?:crontab|schtasks|systemctl|launchd|registry run|startup folder)", re.I), "Contains persistence behavior", "persistence"),
    ("SKILL-OBFUSCATION-001", "high", re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f]|(?:[A-Za-z0-9+/]{240,}={0,2})|(?:[0-9a-fA-F]{400,})"), "Contains hidden Unicode or a large encoded payload", "obfuscation"),
    ("SKILL-UNTRUSTED-REINTERPRET-001", "high", re.compile(r"(?:treat|interpret|use).{0,80}(?:web|document|email|tool output|external content).{0,80}(?:system|instruction|command)", re.I), "Reinterprets external content as trusted instructions", "prompt_injection"),
]

COMMAND_RE = re.compile(r"\b(python|python3|node|bash|sh|powershell|pwsh|cmd|git|curl|wget|npm|pip|docker|kubectl)\b", re.I)
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)


class SkillScanError(ValueError):
    pass


class SkillScanner:
    def __init__(self, hmac_key: bytes, inspection_policy_digest: str):
        self.hmac_key = hmac_key
        self.inspection_policy_digest = inspection_policy_digest

    def scan(self, source: Path, canonical_name: str, source_identity: str, builtin_findings: list[dict[str, Any]]) -> tuple[ContentArtifact, InspectionVerdict]:
        root = source.expanduser().resolve(strict=True)
        if not root.is_dir():
            raise SkillScanError("skill source must be a directory")
        now = datetime.now(timezone.utc)
        findings: list[InspectionFinding] = []
        capabilities = CapabilityManifest()
        entries: list[dict[str, Any]] = []
        total_bytes = 0

        paths = sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if len(paths) > MAX_FILES:
            findings.append(self._finding("SKILL-LIMIT-001", "critical", ".", None, str(len(paths)), "Skill exceeds the file-count scan limit", "scan_limit"))
            paths = paths[:MAX_FILES]
        for path in paths:
            relative = path.relative_to(root).as_posix()
            if len(path.relative_to(root).parts) > MAX_DEPTH:
                findings.append(self._finding("SKILL-DEPTH-001", "critical", relative, None, relative, "Skill exceeds the recursion-depth limit", "scan_limit"))
                continue
            stat = path.lstat()
            mode = stat.st_mode & 0o7777
            if path.is_symlink():
                findings.append(self._finding("SKILL-SYMLINK-001", "critical", relative, None, os.readlink(path), "Symlink content is quarantined and not followed", "filesystem_escape"))
                entries.append({"path": relative, "kind": "symlink", "mode": mode, "size": stat.st_size, "target_digest": hmac_digest_payload(os.readlink(path), self.hmac_key)})
                continue
            if path.is_dir():
                entries.append({"path": relative, "kind": "directory", "mode": mode})
                continue
            if not path.is_file():
                findings.append(self._finding("SKILL-SPECIAL-FILE-001", "critical", relative, None, relative, "Special filesystem entry is not allowed", "unknown_executable"))
                continue
            if stat.st_nlink > 1:
                findings.append(self._finding("SKILL-HARDLINK-001", "high", relative, None, str(stat.st_nlink), "Hard-linked file requires explicit review", "filesystem_escape"))
            total_bytes += stat.st_size
            if total_bytes > MAX_TOTAL_BYTES:
                findings.append(self._finding("SKILL-LIMIT-002", "critical", relative, None, str(total_bytes), "Skill exceeds the total-byte scan limit", "scan_limit"))
                break
            if stat.st_size > MAX_FILE_BYTES:
                findings.append(self._finding("SKILL-LARGE-FILE-001", "high", relative, None, str(stat.st_size), "File exceeds the per-file scan limit", "unknown_content"))
                entries.append({"path": relative, "kind": "oversized", "mode": mode, "size": stat.st_size})
                capabilities.unknown.append(f"oversized:{relative}")
                continue
            data = path.read_bytes()
            entries.append({
                "path": relative, "kind": "file", "mode": mode, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "executable": bool(mode & 0o111),
            })
            if b"\x00" in data:
                findings.append(self._finding("SKILL-BINARY-001", "high", relative, None, str(len(data)), "Binary or unknown executable content requires review", "unknown_executable"))
                capabilities.unknown.append(f"binary:{relative}")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                findings.append(self._finding("SKILL-ENCODING-001", "high", relative, None, str(len(data)), "Non-UTF-8 content requires review", "unknown_content"))
                capabilities.unknown.append(f"encoding:{relative}")
                continue
            self._scan_text(relative, text, findings, capabilities)

        for item in builtin_findings[:1000]:
            severity = str(item.get("severity", "high")).lower()
            if severity not in {"info", "low", "medium", "high", "critical"}:
                severity = "high"
            findings.append(self._finding(
                str(item.get("rule_id", "OPENCLAW-BUILTIN-001"))[:128], severity,
                str(item.get("file", "."))[:1024], item.get("line") if isinstance(item.get("line"), int) else None,
                item, "OpenClaw builtin scan reported a finding", str(item.get("capability", "builtin_unknown"))[:128],
            ))

        entries.sort(key=lambda item: item["path"])
        content_digest = digest_payload({"kind": "skill", "name": canonical_name, "entries": entries})
        manifest = {
            "scanner_version": SCANNER_VERSION, "files": len(entries), "total_bytes": total_bytes,
            "max_files": MAX_FILES, "max_total_bytes": MAX_TOTAL_BYTES, "max_depth": MAX_DEPTH,
            "entries": entries,
        }
        clean_manifest, _ = sanitize(manifest)
        clean_name, _ = sanitize(canonical_name[:256])
        clean_source, _ = sanitize(source_identity[:512])
        artifact = ContentArtifact(
            kind="skill", canonical_name=str(clean_name), source_identity=str(clean_source),
            content_digest=content_digest, manifest=clean_manifest, first_seen_at=now, last_seen_at=now,
        )
        severities = {finding.severity for finding in findings}
        quarantine_rules = {"SKILL-SYMLINK-001", "SKILL-SPECIAL-FILE-001", "SKILL-LIMIT-001", "SKILL-LIMIT-002"}
        if any(finding.rule_id in quarantine_rules for finding in findings):
            decision, risk = InspectionDecision.QUARANTINE, "critical"
        elif "critical" in severities:
            decision, risk = InspectionDecision.DENY, "critical"
        elif severities & {"high", "medium"} or capabilities.unknown:
            decision, risk = InspectionDecision.REQUIRE_APPROVAL, "high" if "high" in severities else "medium"
        else:
            decision, risk = InspectionDecision.ALLOW, "low" if findings else "info"
        verdict = InspectionVerdict(
            artifact_id=artifact.artifact_id, decision=decision, risk=risk,
            scanner_version=SCANNER_VERSION, inspection_policy_digest=self.inspection_policy_digest,
            findings=findings, capability_manifest=capabilities,
            created_at=now, expires_at=now + timedelta(days=7),
        )
        return artifact, verdict

    def _scan_text(self, relative: str, text: str, findings: list[InspectionFinding], capabilities: CapabilityManifest) -> None:
        for rule_id, severity, pattern, message, capability in RULES:
            for match in list(pattern.finditer(text))[:20]:
                line = text.count("\n", 0, match.start()) + 1
                findings.append(self._finding(rule_id, severity, relative, line, match.group(0), message, capability))
        commands = {match.group(1).lower() for match in COMMAND_RE.finditer(text)}
        capabilities.commands = sorted(set(capabilities.commands) | commands)
        if commands:
            capabilities.tools = sorted(set(capabilities.tools) | {"exec"})
        for raw in URL_RE.findall(text):
            host = (urlsplit(raw.rstrip(".,);]")).hostname or "").lower()
            if host:
                capabilities.network_read = sorted(set(capabilities.network_read) | {host})
                capabilities.tools = sorted(set(capabilities.tools) | {"web_fetch"})
        rule_ids = {finding.rule_id for finding in findings}
        capabilities.dynamic_execution = "SKILL-DYNAMIC-EXEC-001" in rule_ids
        capabilities.secret_access = "SKILL-SECRET-READ-001" in rule_ids
        capabilities.persistence = "SKILL-PERSISTENCE-001" in rule_ids
        if "SKILL-NETWORK-WRITE-001" in rule_ids:
            capabilities.network_write = sorted(set(capabilities.network_write) | set(capabilities.network_read) or {"unknown"})

    def _finding(self, rule_id: str, severity: str, file: str, line: int | None, evidence: Any, message: str, capability: str | None) -> InspectionFinding:
        return InspectionFinding(
            rule_id=rule_id, severity=severity, file=file, line=line,
            evidence_digest=hmac_digest_payload({"file": file, "line": line, "evidence": evidence}, self.hmac_key),
            message=message, capability=capability,
        )
