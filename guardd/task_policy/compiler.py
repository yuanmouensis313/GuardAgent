from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from guardd.security import digest_payload, sanitize
from guardd.task_policy.hybrid_synthesizer import domain_alias_map, path_alias_map
from guardd.task_policy.models import TaskPolicy
from guardd.task_policy.proposal_models import TaskPolicyProposal, TrustedTaskContext


@dataclass(frozen=True)
class TaskPolicyCompileResult:
    policy: TaskPolicy
    proposal_digest: str
    accepted_fields: list[str]
    rejected_fields: list[dict[str, str]]
    uncertainties: list[str]


class TaskPolicyProposalValidator:
    def __init__(self, secret_patterns=None):
        self.secret_patterns = secret_patterns or []

    def validate(self, payload: dict[str, Any]) -> TaskPolicyProposal:
        clean, classifications = sanitize(payload, extra_patterns=self.secret_patterns)
        if classifications:
            raise ValueError("TASK_POLICY_PROPOSAL_SECRET_ECHO")
        try:
            return TaskPolicyProposal.model_validate(clean)
        except ValidationError as exc:
            raise ValueError("TASK_POLICY_PROPOSAL_SCHEMA_INVALID") from exc


class TaskPolicyCompiler:
    _MODEL_FORBIDDEN_TOOLS = {
        "exec", "message_send", "sessions_spawn", "subagent_spawn",
    }

    def __init__(
        self,
        *,
        allow_model_read_expansion: bool = True,
        allow_model_write_expansion: bool = False,
    ):
        self.allow_model_read_expansion = allow_model_read_expansion
        self.allow_model_write_expansion = allow_model_write_expansion

    def compile(
        self,
        *,
        context: TrustedTaskContext,
        draft: TaskPolicy,
        proposal: TaskPolicyProposal,
        generation_id: str,
        model: str,
        prompt_digest: str,
    ) -> TaskPolicyCompileResult:
        if context.session_key != draft.session_key or context.agent_id != draft.agent_id:
            raise ValueError("TASK_POLICY_CONTEXT_BINDING_MISMATCH")
        accepted: list[str] = []
        rejected: list[dict[str, str]] = []
        supported = self._supported_fields(context, proposal, rejected)
        compiled = draft.model_copy(deep=True)
        registered = set(context.registered_tools)

        for category, tools in (
            ("required", proposal.tools.required),
            ("optional", proposal.tools.optional),
        ):
            for index, tool in enumerate(tools):
                field = f"$.tools.{category}[{index}]"
                if tool not in registered:
                    rejected.append({"field": field, "reason": "unknown_tool"})
                    continue
                if field not in supported:
                    rejected.append({"field": field, "reason": "missing_evidence"})
                    continue
                if tool in self._MODEL_FORBIDDEN_TOOLS and tool not in compiled.tools.allow:
                    rejected.append({"field": field, "reason": "model_cannot_expand_sensitive_tool"})
                    continue
                if tool in {"write", "edit", "apply_patch"} and not compiled.files.write:
                    rejected.append({"field": field, "reason": "no_explicit_write_target"})
                    continue
                if tool in {"web_fetch", "browser"} and not (compiled.network.read or compiled.network.write):
                    rejected.append({"field": field, "reason": "no_explicit_network_target"})
                    continue
                if tool not in compiled.tools.allow:
                    if not self.allow_model_read_expansion:
                        rejected.append({"field": field, "reason": "model_tool_expansion_disabled"})
                        continue
                    compiled.tools.allow.append(tool)
                accepted.append(field)

        for index, tool in enumerate(proposal.tools.deny):
            field = f"$.tools.deny[{index}]"
            if tool not in registered:
                rejected.append({"field": field, "reason": "unknown_tool"})
                continue
            if tool not in compiled.tools.deny:
                compiled.tools.deny.append(tool)
            accepted.append(field)

        paths = path_alias_map(draft)
        self._accept_aliases(
            proposal.files.read, "$.files.read", "read", paths, supported,
            compiled.files.read, accepted, rejected,
        )
        self._accept_aliases(
            proposal.files.write, "$.files.write", "write", paths, supported,
            compiled.files.write, accepted, rejected,
            enabled=self.allow_model_write_expansion,
        )
        domains = domain_alias_map(draft)
        self._accept_aliases(
            proposal.network.read, "$.network.read", "read", domains, supported,
            compiled.network.read, accepted, rejected,
        )
        self._accept_aliases(
            proposal.network.write, "$.network.write", "write", domains, supported,
            compiled.network.write, accepted, rejected,
            enabled=self.allow_model_write_expansion,
        )

        for index, prefix in enumerate(proposal.commands.allow_prefixes):
            field = f"$.commands.allow_prefixes[{index}]"
            if prefix in compiled.commands.allow_prefixes:
                accepted.append(field)
            else:
                rejected.append({"field": field, "reason": "model_command_expansion_forbidden"})
        for index, category in enumerate(proposal.commands.approval_categories):
            field = f"$.commands.approval_categories[{index}]"
            if category not in compiled.commands.approval_categories:
                compiled.commands.approval_categories.append(category)
            accepted.append(field)

        compiled.limits.max_tool_calls = min(
            compiled.limits.max_tool_calls,
            proposal.limits.max_tool_calls,
        )
        compiled.limits.max_external_writes = min(
            compiled.limits.max_external_writes,
            proposal.limits.max_external_writes,
        )
        compiled.limits.max_files_changed = min(
            compiled.limits.max_files_changed,
            proposal.limits.max_files_changed,
        )
        compiled.limits.expires_at = min(
            compiled.limits.expires_at,
            datetime.now(timezone.utc) + timedelta(minutes=proposal.limits.ttl_minutes),
        )
        accepted.extend([
            "$.limits.max_tool_calls",
            "$.limits.max_external_writes",
            "$.limits.max_files_changed",
            "$.limits.ttl_minutes",
        ])

        compiled.tools.allow = sorted(set(compiled.tools.allow) - set(compiled.tools.deny))
        compiled.tools.deny = sorted(set(compiled.tools.deny))
        compiled.commands.approval_categories = sorted(set(compiled.commands.approval_categories))
        clean_uncertainties, _ = sanitize(proposal.uncertainties)
        uncertainties = [str(item)[:512] for item in clean_uncertainties]
        proposal_digest = digest_payload(proposal.model_dump(mode="json"))
        compiled.provenance.generator = "hybrid"
        compiled.provenance.generator_version = "1"
        compiled.provenance.model = model
        compiled.provenance.prompt_digest = prompt_digest
        compiled.provenance.generation_id = generation_id
        compiled.provenance.proposal_digest = proposal_digest
        compiled.provenance.accepted_fields = sorted(set(accepted))
        compiled.provenance.rejected_fields = rejected[:500]
        compiled.provenance.uncertainties = uncertainties[:100]
        compiled.policy_digest = digest_payload(compiled.digest_payload())
        return TaskPolicyCompileResult(
            policy=compiled,
            proposal_digest=proposal_digest,
            accepted_fields=compiled.provenance.accepted_fields,
            rejected_fields=rejected,
            uncertainties=uncertainties,
        )

    @staticmethod
    def _supported_fields(
        context: TrustedTaskContext,
        proposal: TaskPolicyProposal,
        rejected: list[dict[str, str]],
    ) -> set[str]:
        supported: set[str] = set()
        prompt_length = len(context.sanitized_user_prompt)
        for index, evidence in enumerate(proposal.evidence):
            field = f"$.evidence[{index}]"
            if (
                evidence.input_span.start >= evidence.input_span.end
                or evidence.input_span.end > prompt_length
            ):
                rejected.append({"field": field, "reason": "invalid_evidence_span"})
                continue
            supported.add(evidence.supports)
        return supported

    @staticmethod
    def _accept_aliases(
        aliases: list[str],
        field_prefix: str,
        expected_kind: str,
        mapping: dict[str, tuple[str, str]],
        supported: set[str],
        target: list[str],
        accepted: list[str],
        rejected: list[dict[str, str]],
        *,
        enabled: bool = True,
    ) -> None:
        for index, alias in enumerate(aliases):
            field = f"{field_prefix}[{index}]"
            bound = mapping.get(alias)
            if bound is None or bound[0] != expected_kind:
                rejected.append({"field": field, "reason": "unknown_or_mismatched_alias"})
                continue
            if field not in supported:
                rejected.append({"field": field, "reason": "missing_evidence"})
                continue
            if not enabled and bound[1] not in target:
                rejected.append({"field": field, "reason": "model_expansion_disabled"})
                continue
            if bound[1] not in target:
                target.append(bound[1])
            accepted.append(field)
