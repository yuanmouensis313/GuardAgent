from __future__ import annotations

from guardd.models.events import Origin
from guardd.security import sanitize
from guardd.task_policy.models import TaskPolicy
from guardd.task_policy.proposal_models import (
    TrustedDomainAlias,
    TrustedOrigin,
    TrustedPathAlias,
    TrustedTaskContext,
)


DEFAULT_REGISTERED_TOOLS = [
    "apply_patch", "browser", "edit", "exec", "glob", "health", "list",
    "message_send", "read", "search", "sessions_spawn", "status", "web_fetch", "write",
]


class TrustedTaskContextBuilder:
    def __init__(self, registered_tools: list[str] | None = None):
        self.registered_tools = sorted(set(registered_tools or DEFAULT_REGISTERED_TOOLS))

    def build(
        self,
        *,
        prompt: str,
        draft: TaskPolicy,
        origin: Origin | None,
        active_task_summary: str | None = None,
    ) -> TrustedTaskContext:
        clean_prompt, _ = sanitize(prompt)
        sanitized_prompt = str(clean_prompt).strip()[:100_000] or "Task objective withheld after sanitization"
        path_aliases: list[TrustedPathAlias] = []
        index = 1
        for access, paths in (("read", draft.files.read), ("write", draft.files.write)):
            for _ in paths:
                path_aliases.append(TrustedPathAlias(alias=f"PATH_{index}", access=access))
                index += 1
        domain_aliases: list[TrustedDomainAlias] = []
        index = 1
        for direction, domains in (("read", draft.network.read), ("write", draft.network.write)):
            for _ in domains:
                domain_aliases.append(TrustedDomainAlias(alias=f"DOMAIN_{index}", direction=direction))
                index += 1
        return TrustedTaskContext(
            session_key=draft.session_key,
            agent_id=draft.agent_id,
            parent_policy_digest=draft.parent_policy_digest,
            sanitized_user_prompt=sanitized_prompt,
            origin=TrustedOrigin(
                channel=origin.channel if origin else draft.provenance.origin_channel or "local",
                sender_digest=draft.provenance.origin_sender_digest,
                is_local_operator=origin.is_local_operator if origin else draft.provenance.origin_is_local_operator,
            ),
            path_aliases=path_aliases,
            domain_aliases=domain_aliases,
            registered_tools=self.registered_tools,
            base_constraints_digest=draft.base_policy_digest,
            active_task_summary=active_task_summary,
        )


def path_alias_map(draft: TaskPolicy) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    index = 1
    for access, paths in (("read", draft.files.read), ("write", draft.files.write)):
        for path in paths:
            result[f"PATH_{index}"] = (access, path)
            index += 1
    return result


def domain_alias_map(draft: TaskPolicy) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    index = 1
    for direction, domains in (("read", draft.network.read), ("write", draft.network.write)):
        for domain in domains:
            result[f"DOMAIN_{index}"] = (direction, domain)
            index += 1
    return result
