from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("authorization", re.compile(r"(?i)\b(?:authorization|api[_-]?key|token|password|cookie)\s*[:=]\s*[^\s,;]+")),
    ("connection_string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+")),
    ("cn_id", re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)")),
]
OPTIONAL_PATTERNS = {
    "phone": ("phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    "email": ("email", re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")),
}

SENSITIVE_PATH_PARTS = {
    ".env", ".ssh", ".gnupg", ".aws", ".docker", ".kube", "credentials",
    "id_rsa", "id_ed25519", "keychain", "login data", "cookies", "exec-approvals.json",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_payload(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()
    return f"sha256:{sha256_bytes(encoded)}"


def summarize_value(value: Any) -> Any:
    if isinstance(value, str):
        return {"type": "string", "len": len(value), "sha256": sha256_bytes(value.encode())[:16]}
    if isinstance(value, bytes):
        return {"type": "bytes", "len": len(value), "sha256": sha256_bytes(value)[:16]}
    if isinstance(value, dict):
        return {"type": "object", "keys": sorted(str(key) for key in value)[:100], "sha256": digest_payload(value)[7:23]}
    if isinstance(value, list):
        return {"type": "array", "len": len(value), "sha256": digest_payload(value)[7:23]}
    return value


def summarize_mapping(value: dict[str, Any]) -> dict[str, Any]:
    return {str(key): summarize_value(item) for key, item in value.items()}


def _secret_marker(kind: str, value: str) -> str:
    return f'<SECRET type="{kind}" len="{len(value)}" sha256="{sha256_bytes(value.encode())[:12]}">'


def build_extra_patterns(config: dict[str, Any] | None) -> list[tuple[str, re.Pattern[str]]]:
    config = config or {}
    patterns: list[tuple[str, re.Pattern[str]]] = []
    if config.get("detect_phone", False):
        patterns.append(OPTIONAL_PATTERNS["phone"])
    if config.get("detect_email", False):
        patterns.append(OPTIONAL_PATTERNS["email"])
    for item in config.get("custom_patterns", []):
        patterns.append((str(item["id"]), re.compile(str(item["regex"]))))
    return patterns


def redact_text(value: str, extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None) -> tuple[str, list[str]]:
    found: list[str] = []
    result = value
    for kind, pattern in [*SECRET_PATTERNS, *(extra_patterns or [])]:
        def replace(match: re.Match[str], secret_kind: str = kind) -> str:
            found.append(secret_kind)
            return _secret_marker(secret_kind, match.group(0))
        result = pattern.sub(replace, result)
    return result, sorted(set(found))


def sanitize(value: Any, key: str = "", extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None) -> tuple[Any, list[str]]:
    classifications: list[str] = []
    if any(token in key.lower() for token in ("token", "secret", "password", "cookie", "authorization", "pairing")):
        text = str(value)
        return _secret_marker("sensitive_field", text), ["sensitive_field"]
    if isinstance(value, str):
        return redact_text(value, extra_patterns)
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for child_key, child_value in value.items():
            clean, kinds = sanitize(child_value, str(child_key), extra_patterns)
            output[str(child_key)] = clean
            classifications.extend(kinds)
        return output, sorted(set(classifications))
    if isinstance(value, list):
        output_list = []
        for item in value:
            clean, kinds = sanitize(item, extra_patterns=extra_patterns)
            output_list.append(clean)
            classifications.extend(kinds)
        return output_list, sorted(set(classifications))
    return value, classifications


def contains_sensitive_path(path: str) -> bool:
    lower = path.replace("\\", "/").lower()
    return any(part in lower for part in SENSITIVE_PATH_PARTS)


def ensure_token(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise RuntimeError("guardd token file is invalid")
        return token
    token = secrets.token_urlsafe(48)
    path.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return token
