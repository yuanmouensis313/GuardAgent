from __future__ import annotations

import fnmatch
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardd.models.decisions import DECISION_ORDER, Decision, DecisionKind, RiskLevel
from guardd.models.events import GuardEvent
from guardd.normalizers.command import extract_command, normalize_command
from guardd.normalizers.network import normalize_network_targets
from guardd.normalizers.path import normalize_paths
from guardd.policy.loader import LoadedPolicy
from guardd.security import build_extra_patterns, digest_payload, sanitize


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


class PolicyEngine:
    def __init__(self, policy: LoadedPolicy, workspace: Path, resolve_dns: bool = True):
        self.policy = policy
        self.workspace = workspace.resolve()
        self.resolve_dns = resolve_dns
        document = policy.document
        self.defaults = document.get("defaults", {})
        self.allow_domains = document.get("network", {}).get("allow_domains", [])
        self.deny_domains = document.get("network", {}).get("deny_domains", [])
        self.secret_patterns = build_extra_patterns(document.get("secret_detection"))
        configured = [Path(item).expanduser() for item in document.get("protected_paths", []) if "${" not in item]
        self.protected_paths = [Path(__file__).parents[2].resolve(), policy.source.parent.resolve(), *configured]

    def normalize(self, event: GuardEvent) -> GuardEvent:
        _, classifications = sanitize(event.params, extra_patterns=self.secret_patterns)
        event.data_classification = sorted(set(event.data_classification + classifications))
        derived = dict(event.derived)
        derived["guardd_version"] = "0.1.0"
        tool_name = event.tool.name.lower() if event.tool else ""
        command_text = extract_command(event.params)
        command_info = normalize_command(command_text, event.tool.input_kind if event.tool else None) if command_text else {"commands": [], "dynamic_eval": False, "parse_failed": False, "shell_features": []}
        derived.update(command_info)
        params_with_hints = dict(event.params)
        host_hints = derived.get("host_derived_paths", [])
        if isinstance(host_hints, list):
            params_with_hints["derivedpaths"] = host_hints
        derived["paths"] = normalize_paths(params_with_hints, self.workspace, tool_name, command_info["commands"], self.protected_paths)
        derived["network_targets"] = normalize_network_targets(event.params, self.allow_domains, self.deny_domains, self.resolve_dns)
        derived["actions"] = self._actions(event, derived)
        payload_bytes = sum(
            len(value.encode("utf-8")) for key, value in event.params.items()
            if key.lower() in {"content", "data", "body", "patch", "diff", "input"} and isinstance(value, str)
        )
        derived["file_metrics"] = {
            "file_count": len(derived["paths"]),
            "total_bytes": int(event.params.get("total_bytes", payload_bytes) or 0),
            "delete_count": int(event.params.get("delete_count", 0) or 0),
            "delete_ratio": float(event.params.get("delete_ratio", 0.0) or 0.0),
        }
        event.derived = derived
        return event

    def _actions(self, event: GuardEvent, derived: dict[str, Any]) -> list[str]:
        name = event.tool.name.lower() if event.tool else ""
        actions: set[str] = set()
        if name in {"read", "search", "list", "glob"}:
            actions.add("read")
        if name in {"write", "edit", "apply_patch", "delete", "remove", "move", "copy"}:
            actions.add("write" if name not in {"delete", "remove"} else "delete")
        if name in {"message", "message_send", "send", "email", "reply_payload"} or event.event_type.startswith("message"):
            actions.add("external_send")
        for target in derived.get("network_targets", []):
            actions.add("network_write" if target["direction"] == "outbound_write" else "network_read")
        for command in derived.get("commands", []):
            executable = command.get("executable", "")
            argv = [str(x).lower() for x in command.get("argv", [])]
            if executable == "git" and argv and argv[0] in {"push", "fetch", "pull", "clone"}:
                actions.add("remote_write" if argv[0] == "push" else "network_read")
            if executable in {"rm", "del", "rmdir", "remove-item"}:
                actions.add("delete")
            if executable in {"cp", "copy", "copy-item", "mv", "move", "move-item", "set-content", "add-content", "out-file", "touch", "mkdir", "new-item", "chmod", "chown"}:
                actions.add("write")
            if command.get("redirections"):
                actions.add("write")
            if executable in {"cat", "type", "get-content", "more", "less", "head", "tail"}:
                actions.add("read")
            if executable in {"curl", "wget", "invoke-webrequest", "invoke-restmethod"}:
                actions.add("network_read")
            if executable in {"npm", "pip", "pip3", "pnpm", "yarn", "cargo", "apt", "apt-get", "winget", "choco"} and "install" in argv:
                actions.add("install")
            if executable in {"schtasks", "crontab", "systemctl", "sc", "reg"}:
                actions.add("persistence")
            if executable in {"docker", "podman"}:
                actions.add("container")
            if executable in {"start-process", "stop-process", "kill", "taskkill"}:
                actions.add("process")
        return sorted(actions)

    def decide(self, event: GuardEvent, correlation_matches: list[dict[str, str]] | None = None) -> Decision:
        if "guardd_version" not in event.derived:
            event = self.normalize(event)
        matches: list[dict[str, Any]] = []
        ordered_rules = sorted(self.policy.document.get("rules", []), key=lambda item: int(item.get("priority", 0)), reverse=True)
        for rule in ordered_rules:
            if self._matches(rule.get("match", {}), event):
                matches.append(rule)
        rewritten_params: dict[str, Any] | None = None
        bound_event = event
        for item in matches:
            if isinstance(item.get("rewrite"), dict):
                rewritten_params = {**event.params, **item["rewrite"]}
                bound_event = self.normalize(event.model_copy(deep=True, update={"params": rewritten_params, "derived": {}}))
                for rule in ordered_rules:
                    if rule not in matches and self._matches(rule.get("match", {}), bound_event):
                        matches.append(rule)
                event.derived["parameter_rewrite"] = {
                    "keys": sorted(item["rewrite"]),
                    "rewritten_digest": digest_payload(rewritten_params),
                }
                break
        matches.extend(correlation_matches or [])
        if matches:
            strictness = max(DECISION_ORDER[DecisionKind(str(item["decision"]).upper())] for item in matches)
            strict_matches = [item for item in matches if DECISION_ORDER[DecisionKind(str(item["decision"]).upper())] == strictness]
            chosen = max(strict_matches, key=lambda item: (RiskLevel[str(item.get("risk", "medium"))], int(item.get("priority", 0))))
            proposed = DecisionKind(str(chosen["decision"]).upper())
            risk = str(max((RiskLevel[str(item.get("risk", "medium"))] for item in matches), default=RiskLevel.medium).name)
            rule_ids = [str(item["id"]) for item in matches]
            reason = "; ".join(dict.fromkeys(str(item.get("reason", item["id"])) for item in matches))
        else:
            proposed = DecisionKind(str(self.defaults.get("decision", "require_approval")).upper())
            risk = "medium"
            rule_ids = ["DEFAULT-000"]
            reason = "No explicit rule matched; conservative default applied"

        mode = self.policy.mode
        effective = proposed
        if mode == "observe":
            effective = DecisionKind.OBSERVE
        bound_params = rewritten_params if rewritten_params is not None else event.params
        clean_params, classifications = sanitize(bound_params, extra_patterns=self.secret_patterns)
        event.data_classification = sorted(set(event.data_classification + classifications))
        binding = {
            "agent_id": event.agent_id, "session_key": event.session_key,
            "run_id": event.run_id, "sender_id": event.origin.sender_id,
            "tool": event.tool.model_dump() if event.tool else None,
            "params": bound_params, "cwd": bound_params.get("cwd"),
            "paths": bound_event.derived.get("paths", []), "network_targets": bound_event.derived.get("network_targets", []),
        }
        return Decision(
            event_id=event.event_id, decision=effective,
            would_decide=proposed if effective != proposed else None,
            risk=risk, rule_ids=rule_ids, reason=reason, effective_mode=mode,
            parameter_digest=digest_payload(binding), sanitized_params=clean_params,
            rewritten_params=rewritten_params,
            remediation="Review the normalized target and approve once" if effective == DecisionKind.REQUIRE_APPROVAL else None,
        )

    def _matches(self, match: dict[str, Any], event: GuardEvent) -> bool:
        tool = event.tool
        derived = event.derived
        commands = derived.get("commands", [])
        paths = derived.get("paths", [])
        targets = derived.get("network_targets", [])
        checks: list[bool] = []
        for key, expected in match.items():
            expected_values = [str(x).lower() for x in _as_list(expected)]
            if key == "tool":
                checks.append(bool(tool) and any(fnmatch.fnmatch(tool.name.lower(), pattern) for pattern in expected_values))
            elif key == "tool_kind":
                checks.append(bool(tool) and tool.kind.lower() in expected_values)
            elif key == "event_type":
                checks.append(any(fnmatch.fnmatch(event.event_type.lower(), pattern) for pattern in expected_values))
            elif key == "action":
                checks.append(bool(set(expected_values) & set(derived.get("actions", []))))
            elif key == "executable":
                checks.append(any(c.get("executable", "").lower() in expected_values for c in commands))
            elif key == "argv_prefix":
                prefix = [str(x).lower() for x in expected]
                checks.append(any([str(x).lower() for x in c.get("argv", [])][:len(prefix)] == prefix for c in commands))
            elif key == "argv_prefix_any":
                prefixes = [[str(x).lower() for x in prefix] for prefix in expected]
                checks.append(any(any([str(x).lower() for x in c.get("argv", [])][:len(prefix)] == prefix for prefix in prefixes) for c in commands))
            elif key in {"dynamic_eval", "parse_failed"}:
                checks.append(bool(derived.get(key)) is bool(expected))
            elif key == "shell_feature":
                checks.append(bool(set(expected_values) & set(derived.get("shell_features", []))))
            elif key == "path_group":
                checks.append(any(p.get("path_group") in expected_values for p in paths))
            elif key == "path_access":
                checks.append(any(p.get("access") in expected_values for p in paths))
            elif key == "network_classification":
                checks.append(any(t.get("classification") in expected_values for t in targets))
            elif key == "network_direction":
                checks.append(any(t.get("direction") in expected_values for t in targets))
            elif key == "data_classification":
                checks.append(bool(event.data_classification) if "*" in expected_values else bool(set(expected_values) & {x.lower() for x in event.data_classification}))
            elif key == "agent":
                checks.append(any(fnmatch.fnmatch(event.agent_id.lower(), pattern) for pattern in expected_values))
            elif key == "session":
                checks.append(any(fnmatch.fnmatch(event.session_key.lower(), pattern) for pattern in expected_values))
            elif key == "run":
                checks.append(any(fnmatch.fnmatch((event.run_id or "").lower(), pattern) for pattern in expected_values))
            elif key == "channel":
                checks.append(event.origin.channel.lower() in expected_values)
            elif key == "sender":
                checks.append((event.origin.sender_id or "").lower() in expected_values)
            elif key == "is_local_operator":
                checks.append(event.origin.is_local_operator is bool(expected))
            elif key == "command_regex":
                checks.append(any(re.search(str(expected), c.get("raw", ""), re.IGNORECASE) is not None for c in commands))
            elif key == "param_present":
                checks.append(any(item in event.params for item in _as_list(expected)))
            elif key == "param_regex":
                checks.append(re.search(str(expected), json.dumps(event.params, ensure_ascii=False, default=str), re.IGNORECASE | re.DOTALL) is not None)
            elif key == "time_window":
                now = datetime.now(timezone.utc).strftime("%H:%M")
                checks.append(str(expected.get("start", "00:00")) <= now <= str(expected.get("end", "23:59")))
            else:
                checks.append(False)
        return all(checks) if checks else False
