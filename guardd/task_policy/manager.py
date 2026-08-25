from __future__ import annotations

import fnmatch
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from guardd.audit.store import AuditStore
from guardd.models.events import GuardEvent
from guardd.models.events import Origin
from guardd.security import digest_payload, ensure_hmac_key, hmac_digest_payload
from guardd.task_policy.models import TaskPolicy, TaskPolicyStatus
from guardd.task_policy.synthesizer import DeterministicTaskPolicySynthesizer


class TaskPolicyError(ValueError):
    pass


def _matches_name(value: str, patterns: list[str]) -> bool:
    lower = value.lower()
    return any(fnmatch.fnmatch(lower, pattern.lower()) for pattern in patterns)


def _matches_path(value: str, patterns: list[str]) -> bool:
    normalized = os.path.normcase(str(Path(value).resolve(strict=False)))
    for pattern in patterns:
        if "*" in pattern or "?" in pattern:
            normalized_pattern = os.path.normcase(pattern)
        else:
            normalized_pattern = os.path.normcase(str(Path(pattern).resolve(strict=False)))
        if fnmatch.fnmatch(normalized, normalized_pattern):
            return True
    return False


def _matches_domain(host: str, patterns: list[str]) -> bool:
    lower = host.rstrip(".").lower()
    for pattern in patterns:
        expected = pattern.rstrip(".").lower()
        if fnmatch.fnmatch(lower, expected) or lower == expected or lower.endswith("." + expected):
            return True
    return False


class TaskPolicyManager:
    def __init__(
        self, store: AuditStore, workspace: Path, hmac_key_path: Path,
        base_policy_digest: str, mode: str = "observe",
        ttl_minutes: int = 120, out_of_scope: str = "require_approval",
    ):
        if mode not in {"observe", "approval", "enforce"}:
            raise ValueError("task policy mode must be observe, approval, or enforce")
        if out_of_scope not in {"require_approval", "deny"}:
            raise ValueError("task policy out_of_scope must be require_approval or deny")
        self.store = store
        self.workspace = workspace.resolve()
        self.base_policy_digest = base_policy_digest
        self.mode = mode
        self.out_of_scope = out_of_scope
        self.synthesizer = DeterministicTaskPolicySynthesizer(
            self.workspace, ensure_hmac_key(hmac_key_path), ttl_minutes,
        )
        self.hmac_key = self.synthesizer.hmac_key
        self._hybrid_lock = threading.RLock()

    def update_base_policy_digest(self, digest: str) -> None:
        self.base_policy_digest = digest

    def capture(
        self, *, prompt: str, session_key: str, agent_id: str,
        parent_session_key: str | None = None, origin: Origin | None = None,
    ) -> TaskPolicy:
        active = self.store.get_task_policy(session_key, TaskPolicyStatus.ACTIVE.value)
        parent = None
        if parent_session_key:
            if parent_session_key == session_key:
                raise TaskPolicyError("a task policy cannot inherit from its own session")
            parent = self.store.get_task_policy(parent_session_key, TaskPolicyStatus.ACTIVE.value)
            if parent is None:
                raise TaskPolicyError("parent session has no active task policy")
        latest_revision = self.store.latest_task_policy_revision(session_key)
        candidate = self.synthesizer.synthesize(
            prompt=prompt,
            session_key=session_key,
            agent_id=agent_id,
            revision=latest_revision + 1,
            base_policy_digest=self.base_policy_digest,
            parent_session_key=parent_session_key,
            parent_policy_digest=parent.policy_digest if parent else None,
            origin=origin,
        )
        if parent is not None:
            self._intersect_with_parent(candidate, parent)
            candidate.policy_digest = digest_payload(candidate.digest_payload())
        if active and active.objective.source_digest == candidate.objective.source_digest:
            return active
        pending = self.store.get_pending_task_policy(session_key)
        if pending and pending.objective.source_digest == candidate.objective.source_digest:
            return pending
        if active and self._same_scope(candidate, active):
            return active
        if active and self._is_narrower(candidate, active):
            candidate.limits.expires_at = min(candidate.limits.expires_at, active.limits.expires_at)
            candidate.policy_digest = digest_payload(candidate.digest_payload())
            self.store.supersede_pending_task_policies(session_key)
            self.store.record_task_policy(candidate)
            activated = self.store.activate_task_policy(
                session_key=session_key,
                candidate_digest=candidate.policy_digest,
                expected_active_revision=active.revision,
                operator="guardd:auto-narrow",
                base_policy_digest=self.base_policy_digest,
            )
            if activated is None:
                raise TaskPolicyError("automatic task-policy narrowing conflicted with a concurrent revision")
            return activated
        if active:
            candidate.status = TaskPolicyStatus.REVISION_CANDIDATE
        self.store.supersede_pending_task_policies(session_key)
        self.store.record_task_policy(candidate)
        return candidate

    @staticmethod
    def _intersect_with_parent(child: TaskPolicy, parent: TaskPolicy) -> None:
        child.tools.allow = [name for name in child.tools.allow if _matches_name(name, parent.tools.allow)]
        child.tools.deny = sorted(set(child.tools.deny) | set(parent.tools.deny))
        child.files.read = [path for path in child.files.read if _matches_path(path, parent.files.read)]
        child.files.write = [path for path in child.files.write if _matches_path(path, parent.files.write)]
        child.files.deny = sorted(set(child.files.deny) | set(parent.files.deny))
        child.network.read = [host for host in child.network.read if _matches_domain(host, parent.network.read)]
        child.network.write = [host for host in child.network.write if _matches_domain(host, parent.network.write)]
        child.network.deny = sorted(set(child.network.deny) | set(parent.network.deny))
        child.commands.allow_prefixes = [
            value for value in child.commands.allow_prefixes
            if any(value.lower().startswith(prefix.lower()) for prefix in parent.commands.allow_prefixes)
        ]
        child.commands.deny_prefixes = sorted(set(child.commands.deny_prefixes) | set(parent.commands.deny_prefixes))
        child.commands.approval_categories = sorted(
            set(child.commands.approval_categories) | set(parent.commands.approval_categories),
        )
        child.skills.allow_digests = sorted(set(child.skills.allow_digests) & set(parent.skills.allow_digests))
        child.skills.deny_names = sorted(set(child.skills.deny_names) | set(parent.skills.deny_names))
        child.mcp.allow_tools = [name for name in child.mcp.allow_tools if _matches_name(name, parent.mcp.allow_tools)]
        child.mcp.allow_descriptor_digests = sorted(
            set(child.mcp.allow_descriptor_digests) & set(parent.mcp.allow_descriptor_digests),
        )
        child.limits.max_tool_calls = min(child.limits.max_tool_calls, parent.limits.max_tool_calls)
        child.limits.max_external_writes = min(child.limits.max_external_writes, parent.limits.max_external_writes)
        child.limits.max_files_changed = min(child.limits.max_files_changed, parent.limits.max_files_changed)
        child.limits.expires_at = min(child.limits.expires_at, parent.limits.expires_at)

    @staticmethod
    def _same_scope(left: TaskPolicy, right: TaskPolicy) -> bool:
        return TaskPolicyManager._scope(left) == TaskPolicyManager._scope(right)

    @staticmethod
    def _scope(policy: TaskPolicy) -> dict[str, frozenset[str] | int]:
        return {
            "tools_allow": frozenset(policy.tools.allow), "tools_deny": frozenset(policy.tools.deny),
            "files_read": frozenset(policy.files.read), "files_write": frozenset(policy.files.write),
            "files_deny": frozenset(policy.files.deny),
            "network_read": frozenset(policy.network.read), "network_write": frozenset(policy.network.write),
            "network_deny": frozenset(policy.network.deny),
            "commands_allow": frozenset(policy.commands.allow_prefixes),
            "commands_deny": frozenset(policy.commands.deny_prefixes),
            "commands_approval": frozenset(policy.commands.approval_categories),
            "skills_allow": frozenset(policy.skills.allow_digests), "skills_deny": frozenset(policy.skills.deny_names),
            "mcp_tools": frozenset(policy.mcp.allow_tools),
            "mcp_descriptors": frozenset(policy.mcp.allow_descriptor_digests),
            "max_tool_calls": policy.limits.max_tool_calls,
            "max_external_writes": policy.limits.max_external_writes,
            "max_files_changed": policy.limits.max_files_changed,
        }

    @staticmethod
    def _is_narrower(candidate: TaskPolicy, active: TaskPolicy) -> bool:
        c, a = TaskPolicyManager._scope(candidate), TaskPolicyManager._scope(active)
        allow_keys = {
            "tools_allow", "files_read", "files_write", "network_read", "network_write",
            "commands_allow", "skills_allow", "mcp_tools", "mcp_descriptors",
        }
        deny_keys = {"tools_deny", "files_deny", "network_deny", "commands_deny", "commands_approval", "skills_deny"}
        limit_keys = {"max_tool_calls", "max_external_writes", "max_files_changed"}
        return (
            all(c[key] <= a[key] for key in allow_keys)  # type: ignore[operator]
            and all(c[key] >= a[key] for key in deny_keys)  # type: ignore[operator]
            and all(c[key] <= a[key] for key in limit_keys)  # type: ignore[operator]
            and c != a
        )

    def get(self, session_key: str, status: TaskPolicyStatus | None = None) -> TaskPolicy | None:
        if status in {TaskPolicyStatus.CANDIDATE, TaskPolicyStatus.REVISION_CANDIDATE}:
            return self.store.get_pending_task_policy(session_key)
        return self.store.get_task_policy(session_key, status.value if status else None)

    @staticmethod
    def _policy_diff(active: TaskPolicy | None, candidate: TaskPolicy | None) -> dict[str, Any]:
        if candidate is None:
            return {}

        def changed(before: list[str], after: list[str]) -> dict[str, list[str]]:
            old, new = set(before), set(after)
            return {"added": sorted(new - old), "removed": sorted(old - new)}

        empty: list[str] = []
        return {
            "from_revision": active.revision if active else None,
            "to_revision": candidate.revision,
            "tools_allow": changed(active.tools.allow if active else empty, candidate.tools.allow),
            "tools_deny": changed(active.tools.deny if active else empty, candidate.tools.deny),
            "files_read": changed(active.files.read if active else empty, candidate.files.read),
            "files_write": changed(active.files.write if active else empty, candidate.files.write),
            "network_read": changed(active.network.read if active else empty, candidate.network.read),
            "network_write": changed(active.network.write if active else empty, candidate.network.write),
            "commands": changed(active.commands.allow_prefixes if active else empty, candidate.commands.allow_prefixes),
            "skills": changed(active.skills.allow_digests if active else empty, candidate.skills.allow_digests),
            "mcp_tools": changed(active.mcp.allow_tools if active else empty, candidate.mcp.allow_tools),
            "limits": {
                "max_tool_calls": {"from": active.limits.max_tool_calls if active else None, "to": candidate.limits.max_tool_calls},
                "max_external_writes": {"from": active.limits.max_external_writes if active else None, "to": candidate.limits.max_external_writes},
                "max_files_changed": {"from": active.limits.max_files_changed if active else None, "to": candidate.limits.max_files_changed},
                "expires_at": {"from": active.limits.expires_at if active else None, "to": candidate.limits.expires_at},
            },
        }

    def session_view(self, session_key: str) -> dict[str, Any]:
        active = self.get(session_key, TaskPolicyStatus.ACTIVE)
        candidate = self.store.get_pending_task_policy(session_key)
        history = self.store.list_task_policies(session_key)
        if not history:
            raise TaskPolicyError("task policy not found")
        return {
            "session_key": session_key,
            "active": active,
            "candidate": candidate,
            "diff": self._policy_diff(active, candidate),
            "history": history,
            "confirmations": self.store.list_task_policy_confirmations(session_key),
        }

    def activate(
        self, session_key: str, candidate_digest: str,
        expected_active_revision: int | None, operator: str,
    ) -> TaskPolicy:
        candidate = self.store.activate_task_policy(
            session_key=session_key,
            candidate_digest=candidate_digest,
            expected_active_revision=expected_active_revision,
            operator=operator,
            base_policy_digest=self.base_policy_digest,
        )
        if candidate is None:
            raise TaskPolicyError("task policy activation conflict or candidate not found")
        return candidate

    def reject(self, session_key: str, candidate_digest: str, operator: str) -> TaskPolicy:
        candidate = self.store.reject_task_policy(session_key, candidate_digest, operator)
        if candidate is None:
            raise TaskPolicyError("task policy candidate not found or no longer pending")
        return candidate

    def revise_content(
        self, session_key: str, kind: str, name: str, content_digest: str,
        expected_active_revision: int,
    ) -> TaskPolicy:
        active = self.get(session_key, TaskPolicyStatus.ACTIVE)
        if active is None or active.revision != expected_active_revision:
            raise TaskPolicyError("task policy content revision conflict")
        candidate = active.model_copy(deep=True)
        candidate.task_policy_id = uuid4()
        candidate.revision = self.store.latest_task_policy_revision(session_key) + 1
        candidate.status = TaskPolicyStatus.REVISION_CANDIDATE
        candidate.created_at = datetime.now(timezone.utc)
        candidate.activated_at = None
        candidate.closed_at = None
        if kind == "skill":
            candidate.skills.allow_digests = sorted(set(candidate.skills.allow_digests) | {content_digest})
        elif kind == "mcp":
            candidate.mcp.allow_tools = sorted(set(candidate.mcp.allow_tools) | {name})
            candidate.mcp.allow_descriptor_digests = sorted(
                set(candidate.mcp.allow_descriptor_digests) | {content_digest},
            )
        else:
            raise TaskPolicyError("content kind must be skill or mcp")
        candidate.policy_digest = digest_payload(candidate.digest_payload())
        self.store.supersede_pending_task_policies(session_key)
        self.store.record_task_policy(candidate)
        return candidate

    def accept_hybrid_candidate(self, policy: TaskPolicy, generation_id: str) -> TaskPolicy | None:
        with self._hybrid_lock:
            if policy.base_policy_digest != self.base_policy_digest:
                return None
            active = self.get(policy.session_key, TaskPolicyStatus.ACTIVE)
            pending = self.store.get_pending_task_policy(policy.session_key)
            if active and active.objective.source_digest != policy.objective.source_digest:
                return None
            if not active and pending and pending.objective.source_digest != policy.objective.source_digest:
                return None
            candidate = policy.model_copy(deep=True)
            candidate.task_policy_id = uuid4()
            candidate.revision = self.store.latest_task_policy_revision(policy.session_key) + 1
            candidate.created_at = datetime.now(timezone.utc)
            candidate.activated_at = None
            candidate.closed_at = None
            candidate.provenance.generation_id = generation_id
            if candidate.parent_session_key:
                parent = self.store.get_task_policy(
                    candidate.parent_session_key,
                    TaskPolicyStatus.ACTIVE.value,
                )
                if parent is None or parent.policy_digest != candidate.parent_policy_digest:
                    return None
                self._intersect_with_parent(candidate, parent)
            candidate.status = (
                TaskPolicyStatus.REVISION_CANDIDATE if active else TaskPolicyStatus.CANDIDATE
            )
            candidate.policy_digest = digest_payload(candidate.digest_payload())
            if active and self._same_scope(candidate, active):
                return active
            self.store.supersede_pending_task_policies(candidate.session_key)
            self.store.record_task_policy(candidate)
            if active and self._is_narrower(candidate, active):
                activated = self.store.activate_task_policy(
                    session_key=candidate.session_key,
                    candidate_digest=candidate.policy_digest,
                    expected_active_revision=active.revision,
                    operator="guardd:hybrid-auto-narrow",
                    base_policy_digest=self.base_policy_digest,
                )
                if activated is None:
                    raise TaskPolicyError("hybrid task-policy narrowing conflicted with a concurrent revision")
                return activated
            return candidate

    def close(self, session_key: str, operator: str) -> int:
        closed = self.store.close_task_policies(session_key, operator)
        return closed + self.store.close_child_task_policies(session_key, f"{operator}:parent-close")

    def evaluate(self, event: GuardEvent) -> list[dict[str, Any]]:
        active = self.get(event.session_key, TaskPolicyStatus.ACTIVE)
        pending = self.store.get_pending_task_policy(event.session_key)
        if pending is not None and (active is None or pending.revision > active.revision):
            event.derived["task_policy"] = {
                "id": str(pending.task_policy_id), "revision": pending.revision,
                "digest": pending.policy_digest, "status": pending.status.value,
                "mode": self.mode, "verdict": "PENDING_CONFIRMATION",
                "active_revision": active.revision if active else None,
            }
            return self._enforcement_rule(
                "TASK-POLICY-PENDING-001",
                "A session task policy is waiting for confirmation; activate or reject it before retrying the tool call",
            )
        inherited_read_only = False
        if active is None and event.parent_session_key:
            parent = self.get(event.parent_session_key, TaskPolicyStatus.ACTIVE)
            if parent is not None:
                active = parent.model_copy(deep=True)
                active.session_key = event.session_key
                active.agent_id = event.agent_id
                active.parent_session_key = event.parent_session_key
                active.parent_policy_digest = parent.policy_digest
                active.tools.allow = [
                    name for name in active.tools.allow
                    if _matches_name(name, ["read", "web_fetch", "search", "list", "glob", "find"])
                ]
                active.files.write = []
                active.network.write = []
                active.commands.allow_prefixes = []
                active.limits.max_external_writes = 0
                active.limits.max_files_changed = 0
                inherited_read_only = True
        if active is None:
            event.derived["task_policy"] = {"status": "missing", "mode": self.mode, "verdict": "OUT_OF_SCOPE"}
            return self._enforcement_rule("TASK-POLICY-MISSING-001", "No active task policy is bound to this session")

        now = datetime.now(timezone.utc)
        if active.limits.expires_at <= now:
            self.store.expire_task_policy(str(active.task_policy_id))
            event.derived["task_policy"] = {
                "id": str(active.task_policy_id), "revision": active.revision,
                "digest": active.policy_digest, "status": "expired", "verdict": "OUT_OF_SCOPE",
            }
            return self._enforcement_rule("TASK-POLICY-EXPIRED-001", "The active task policy has expired")
        if active.base_policy_digest != self.base_policy_digest:
            event.derived["task_policy"] = {
                "id": str(active.task_policy_id), "revision": active.revision,
                "digest": active.policy_digest, "status": "stale", "verdict": "OUT_OF_SCOPE",
            }
            return self._enforcement_rule("TASK-POLICY-STALE-001", "The base policy changed after task authorization")
        if active.parent_session_key:
            parent = self.store.get_task_policy(active.parent_session_key, TaskPolicyStatus.ACTIVE.value)
            if parent is None or parent.policy_digest != active.parent_policy_digest:
                event.derived["task_policy"] = {
                    "id": str(active.task_policy_id), "revision": active.revision,
                    "digest": active.policy_digest, "status": "parent_stale", "verdict": "OUT_OF_SCOPE",
                    "parent_session_key": active.parent_session_key,
                }
                return self._enforcement_rule(
                    "TASK-POLICY-PARENT-STALE-001",
                    "The parent session task policy is missing or changed; child permissions are no longer valid",
                )

        violations = self._violations(active, event)
        verdict = "OUT_OF_SCOPE" if violations else "ALLOW"
        evaluation_details = event.derived.get("task_policy", {})
        event.derived["task_policy"] = {
            **evaluation_details,
            "id": str(active.task_policy_id), "revision": active.revision,
            "digest": active.policy_digest, "status": active.status.value,
            "verdict": verdict, "violations": violations,
            "inherited_read_only": inherited_read_only,
        }
        if violations:
            return self._enforcement_rule("TASK-POLICY-OUT-OF-SCOPE-001", "; ".join(violations))
        if self.mode == "observe":
            return []
        return [{
            "id": "TASK-POLICY-ALLOW-001", "decision": "ALLOW", "risk": "low",
            "reason": "The action is within the active session task policy", "priority": 600,
        }]

    def _enforcement_rule(self, rule_id: str, reason: str) -> list[dict[str, Any]]:
        if self.mode == "observe":
            return []
        decision = "DENY" if self.mode == "enforce" and self.out_of_scope == "deny" else "REQUIRE_APPROVAL"
        return [{
            "id": rule_id, "decision": decision, "risk": "high",
            "reason": reason, "priority": 1850,
        }]

    def _violations(self, policy: TaskPolicy, event: GuardEvent) -> list[str]:
        violations: list[str] = []
        if event.agent_id != policy.agent_id:
            violations.append(f"agent {event.agent_id} does not match the R_task agent binding")
        if policy.provenance.origin_channel and event.origin.channel != policy.provenance.origin_channel:
            violations.append("event channel does not match the R_task origin binding")
        if policy.provenance.origin_sender_digest:
            actual_sender = hmac_digest_payload(event.origin.sender_id, self.hmac_key) if event.origin.sender_id else None
            if actual_sender != policy.provenance.origin_sender_digest:
                violations.append("event sender does not match the R_task origin binding")
        if policy.activated_at is not None:
            usage = self.store.task_policy_usage(policy.session_key, policy.activated_at)
            event.derived.setdefault("task_policy", {})["usage_before_call"] = usage
            if usage["tool_calls"] >= policy.limits.max_tool_calls:
                violations.append(f"R_task tool-call limit {policy.limits.max_tool_calls} is exhausted")
            current_external_write = any(
                item.get("direction") == "outbound_write"
                for item in event.derived.get("network_targets", [])
            )
            if current_external_write and usage["external_writes"] >= policy.limits.max_external_writes:
                violations.append(f"R_task external-write limit {policy.limits.max_external_writes} is exhausted")
            current_write_paths = {
                str(item.get("resolved")) for item in event.derived.get("paths", [])
                if item.get("access") == "write" and item.get("resolved")
            }
            new_write_paths = current_write_paths - set(usage["files_changed"])
            if new_write_paths and len(usage["files_changed"]) + len(new_write_paths) > policy.limits.max_files_changed:
                violations.append(f"R_task changed-file limit {policy.limits.max_files_changed} would be exceeded")
        tool_name = event.tool.name if event.tool else ""
        if tool_name and _matches_name(tool_name, policy.tools.deny):
            violations.append(f"tool {tool_name} is denied by R_task")
        elif tool_name and not _matches_name(tool_name, policy.tools.allow):
            violations.append(f"tool {tool_name} is not allowed by R_task")

        for path in event.derived.get("paths", []):
            resolved = str(path.get("resolved", ""))
            access = str(path.get("access", "read"))
            if _matches_path(resolved, policy.files.deny):
                violations.append(f"path {resolved} is denied by R_task")
                continue
            allowed = policy.files.write if access == "write" else policy.files.read
            if not _matches_path(resolved, allowed):
                violations.append(f"{access} path {resolved} is outside R_task")

        for target in event.derived.get("network_targets", []):
            host = str(target.get("host", ""))
            if _matches_domain(host, policy.network.deny):
                violations.append(f"network target {host} is denied by R_task")
                continue
            allowed = policy.network.write if target.get("direction") == "outbound_write" else policy.network.read
            if not _matches_domain(host, allowed):
                violations.append(f"network target {host} is outside R_task")

        commands = event.derived.get("commands", [])
        for command in commands:
            raw = str(command.get("raw", "")).strip()
            lower = raw.lower()
            if any(lower.startswith(prefix.lower()) for prefix in policy.commands.deny_prefixes):
                violations.append("command prefix is denied by R_task")
            elif policy.commands.allow_prefixes and not any(lower.startswith(prefix.lower()) for prefix in policy.commands.allow_prefixes):
                violations.append("command prefix is outside R_task")
            elif tool_name.lower() == "exec" and not policy.commands.allow_prefixes:
                violations.append("R_task does not authorize any shell command prefix")
        identity = event.content_identity
        if identity and identity.kind == "skill":
            if not identity.digest or identity.digest not in policy.skills.allow_digests:
                violations.append(f"skill {identity.name} digest is outside R_task")
        if identity and identity.kind == "mcp":
            if not _matches_name(identity.name, policy.mcp.allow_tools):
                violations.append(f"MCP tool {identity.name} is outside R_task")
            if not identity.digest or identity.digest not in policy.mcp.allow_descriptor_digests:
                violations.append(f"MCP descriptor {identity.name} digest is outside R_task")
        return list(dict.fromkeys(violations))
