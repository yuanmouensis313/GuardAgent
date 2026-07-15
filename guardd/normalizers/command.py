from __future__ import annotations

import re
import shlex
from typing import Any


INLINE_EVAL = {
    "python": {"-c"}, "python3": {"-c"}, "node": {"-e", "--eval", "-p"},
    "ruby": {"-e"}, "perl": {"-e", "-E"}, "php": {"-r"}, "lua": {"-e"},
    "osascript": {"-e"}, "find": {"-exec", "-execdir"},
}
DYNAMIC_EXECUTABLES = {"eval", "iex", "invoke-expression", "xargs"}
SHELLS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "wsl"}


def _split_shell(command: str) -> tuple[list[str], list[str], bool]:
    parts: list[str] = []
    features: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    opaque = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            current.append(char)
            index += 1
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            current.append(char)
            index += 1
            continue
        if quote is None:
            token = None
            for candidate, feature in (("&&", "and"), ("||", "or"), (";", "sequence"), ("|", "pipeline")):
                if command.startswith(candidate, index):
                    token = candidate
                    features.append(feature)
                    break
            if token:
                if "".join(current).strip():
                    parts.append("".join(current).strip())
                current = []
                index += len(token)
                continue
        current.append(char)
        index += 1
    if quote is not None or escaped:
        opaque = True
    if "".join(current).strip():
        parts.append("".join(current).strip())
    return parts or [command], sorted(set(features)), opaque


def _argv(part: str, shell_type: str) -> tuple[list[str], bool]:
    try:
        return shlex.split(part, posix=shell_type not in {"powershell", "cmd"}), False
    except ValueError:
        return [part], True


def normalize_command(command: str, shell_type: str | None = None) -> dict[str, Any]:
    shell_type = (shell_type or "unknown").lower()
    lower = command.lower()
    if shell_type == "unknown":
        shell_type = "powershell" if any(x in lower for x in ("invoke-", "remove-item", "-encodedcommand")) else "shell"
    parts, features, opaque = _split_shell(command)
    commands: list[dict[str, Any]] = []
    for part in parts:
        argv, parse_failed = _argv(part, shell_type)
        executable = argv[0].strip("'\"").lower() if argv else ""
        executable = executable.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        flags = {arg.lower() for arg in argv[1:]}
        command_substitution = "$(" in part or "`" in part
        variable_expansion = bool(re.search(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})|%[A-Za-z_][A-Za-z0-9_]*%", part))
        wildcards = bool(re.search(r"(?<!\\)[*?\[]", part))
        dynamic = (
            executable in DYNAMIC_EXECUTABLES
            or bool(flags & INLINE_EVAL.get(executable, set()))
            or "-encodedcommand" in flags
            or "${" in part or command_substitution
            or bool(re.search(r"(?:&|\.)\s*\{|\[scriptblock\]", part, re.IGNORECASE))
            or executable in SHELLS and any(arg.lower() in {"-c", "/c", "-command"} for arg in argv[1:])
        )
        redirections = re.findall(r"(?<![<>&])(?:>>?|<)\s*([^\s]+)", part)
        env_assignments = [arg.split("=", 1)[0] for arg in argv if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", arg)]
        commands.append({
            "raw": part,
            "executable": executable,
            "argv": argv[1:],
            "shell_features": features,
            "dynamic_eval": dynamic,
            "parse_failed": parse_failed or opaque,
            "redirections": redirections,
            "environment_keys": env_assignments,
            "variable_expansion": variable_expansion,
            "command_substitution": command_substitution,
            "wildcards": wildcards,
        })
    return {
        "shell_type": shell_type,
        "commands": commands,
        "shell_features": features,
        "parse_failed": opaque or any(c["parse_failed"] for c in commands),
        "dynamic_eval": any(c["dynamic_eval"] for c in commands),
        "variable_expansion": any(c["variable_expansion"] for c in commands),
        "command_substitution": any(c["command_substitution"] for c in commands),
        "wildcards": any(c["wildcards"] for c in commands),
    }


def extract_command(params: dict[str, Any]) -> str | None:
    for key in ("command", "cmd", "script", "code"):
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None
