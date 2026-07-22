from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from guardd.normalizers.network import URL_RE
from guardd.models.events import Origin
from guardd.security import digest_payload, hmac_digest_payload, sanitize
from guardd.task_policy.models import (
    TaskCommandRules,
    TaskFileRules,
    TaskLimits,
    TaskMcpRules,
    TaskNetworkRules,
    TaskObjective,
    TaskPolicy,
    TaskProvenance,
    TaskSkillRules,
    TaskToolRules,
)


PATH_RE = re.compile(
    r"(?P<quoted>['\"](?P<qpath>[^'\"\r\n]+(?:[\\/]|\.[A-Za-z0-9]{1,8})[^'\"\r\n]*)['\"])"
    r"|(?P<plain>(?<![\w:])(?:[A-Za-z]:[\\/]|~[\\/]|[\\/]|\.{1,2}[\\/]|[\w.-]+[\\/])[^\s,;，；。]+)"
    r"|(?P<filename>\b[\w.-]+\.(?:md|txt|json|ya?ml|toml|ini|cfg|py|ts|tsx|js|jsx|csv|xlsx|docx|pdf)\b)",
    re.IGNORECASE,
)
WRITE_WORDS = re.compile(r"(?:写入|保存|创建|生成|修改|编辑|删除|输出到|write|save|create|generate|modify|edit|delete|remove)", re.IGNORECASE)
READ_WORDS = re.compile(r"(?:读取|查看|搜索|汇总|分析|打开|read|view|search|summari[sz]e|analy[sz]e|open)", re.IGNORECASE)

TOOL_KEYWORDS: list[tuple[re.Pattern[str], tuple[str, ...]]] = [
    (re.compile(r"(?:网页|网站|链接|URL|web|website|fetch|http[s]?://)", re.IGNORECASE), ("web_fetch",)),
    (re.compile(r"(?:浏览器|browser|点击|表单|click|form)", re.IGNORECASE), ("browser",)),
    (re.compile(r"(?:发送|邮件|消息|send|email|message)", re.IGNORECASE), ("message_send",)),
    (re.compile(r"(?:命令|终端|shell|command|powershell|bash)", re.IGNORECASE), ("exec",)),
]
TOOL_CALL_LIMIT_RE = re.compile(
    r"(?:最多(?:调用)?|不超过|至多|at most|no more than)\s*(\d{1,5})\s*(?:次)?\s*(?:工具|tool)?(?:调用|calls?)?",
    re.IGNORECASE,
)


class TaskPolicySynthesizer(Protocol):
    """Injection point for a schema-constrained hybrid synthesizer.

    Implementations must accept only the trusted H0 inputs represented here;
    external/tool content is deliberately absent from the interface.
    """

    def synthesize(
        self, *, prompt: str, session_key: str, agent_id: str,
        revision: int, base_policy_digest: str,
        parent_session_key: str | None = None,
        parent_policy_digest: str | None = None,
        origin: Origin | None = None,
    ) -> TaskPolicy: ...


def _resolve_task_path(raw: str, workspace: Path) -> str | None:
    value = raw.strip().strip("'\"").rstrip(".。,:，；;)]}")
    if not value or "://" in value:
        return None
    try:
        expanded = os.path.expandvars(os.path.expanduser(value))
        candidate = Path(expanded)
        if not candidate.is_absolute():
            candidate = workspace / candidate
        resolved = str(candidate.resolve(strict=False))
        return str(Path(resolved) / "**") if value.endswith(("/", "\\")) else resolved
    except (OSError, ValueError):
        return None


def _path_intent(prompt: str, start: int, end: int) -> str:
    window_start = max(0, start - 64)
    window_end = min(len(prompt), end + 64)
    context = prompt[window_start:window_end]
    center = (start + end) / 2
    intents: list[tuple[float, str]] = []
    for kind, pattern in (("write", WRITE_WORDS), ("read", READ_WORDS)):
        for match in pattern.finditer(context):
            absolute_center = window_start + (match.start() + match.end()) / 2
            intents.append((abs(absolute_center - center), kind))
    return min(intents, default=(0, "read"), key=lambda item: item[0])[1]


class DeterministicTaskPolicySynthesizer:
    version = "1"

    def __init__(self, workspace: Path, hmac_key: bytes, ttl_minutes: int = 120):
        self.workspace = workspace.resolve()
        self.hmac_key = hmac_key
        self.ttl_minutes = max(1, min(ttl_minutes, 24 * 60))

    def synthesize(
        self, *, prompt: str, session_key: str, agent_id: str,
        revision: int, base_policy_digest: str,
        parent_session_key: str | None = None,
        parent_policy_digest: str | None = None,
        origin: Origin | None = None,
    ) -> TaskPolicy:
        now = datetime.now(timezone.utc)
        clean_prompt, _ = sanitize(prompt)
        summary = str(clean_prompt).strip()[:512] or "Task objective withheld after sanitization"
        read_paths: set[str] = set()
        write_paths: set[str] = set()
        url_spans = [match.span() for match in URL_RE.finditer(prompt)]
        for match in PATH_RE.finditer(prompt):
            if any(start <= match.start() < end for start, end in url_spans):
                continue
            raw = match.group("qpath") or match.group("plain") or match.group("filename") or ""
            resolved = _resolve_task_path(raw, self.workspace)
            if not resolved:
                continue
            if _path_intent(prompt, match.start(), match.end()) == "write":
                write_paths.add(resolved)
            else:
                read_paths.add(resolved)

        read_domains: set[str] = set()
        write_domains: set[str] = set()
        has_write_intent = bool(WRITE_WORDS.search(prompt))
        for raw_url in URL_RE.findall(prompt):
            try:
                host = (urlsplit(raw_url.rstrip(".,);]")).hostname or "").lower()
            except ValueError:
                continue
            if not host:
                continue
            if has_write_intent and re.search(r"(?:上传|提交|发送)|\b(?:post|upload|submit)\b", prompt, re.IGNORECASE):
                write_domains.add(host)
            else:
                read_domains.add(host)

        tools: set[str] = set()
        if read_paths:
            tools.add("read")
        if write_paths:
            tools.update({"write", "edit", "apply_patch"})
        if read_domains or write_domains:
            tools.add("web_fetch")
        for pattern, names in TOOL_KEYWORDS:
            if pattern.search(prompt):
                tools.update(names)
        limit_match = TOOL_CALL_LIMIT_RE.search(prompt)
        max_tool_calls = min(10_000, max(1, int(limit_match.group(1)))) if limit_match else 30

        policy = TaskPolicy(
            session_key=session_key,
            agent_id=agent_id,
            parent_session_key=parent_session_key,
            parent_policy_digest=parent_policy_digest,
            revision=revision,
            base_policy_digest=base_policy_digest,
            objective=TaskObjective(
                summary=summary,
                source_digest=hmac_digest_payload(prompt, self.hmac_key),
            ),
            tools=TaskToolRules(allow=sorted(tools)),
            files=TaskFileRules(read=sorted(read_paths), write=sorted(write_paths)),
            network=TaskNetworkRules(read=sorted(read_domains), write=sorted(write_domains)),
            commands=TaskCommandRules(),
            skills=TaskSkillRules(),
            mcp=TaskMcpRules(),
            limits=TaskLimits(
                max_tool_calls=max_tool_calls,
                max_external_writes=len(write_domains),
                max_files_changed=len(write_paths),
                expires_at=now + timedelta(minutes=self.ttl_minutes),
            ),
            provenance=TaskProvenance(
                generator="deterministic",
                generator_version=self.version,
                prompt_digest=digest_payload("guardagent-task-policy-deterministic-v1"),
                origin_channel=origin.channel if origin else None,
                origin_sender_digest=hmac_digest_payload(origin.sender_id, self.hmac_key) if origin and origin.sender_id else None,
                origin_is_local_operator=origin.is_local_operator if origin else False,
            ),
            created_at=now,
        )
        policy.policy_digest = digest_payload(policy.digest_payload())
        return policy
