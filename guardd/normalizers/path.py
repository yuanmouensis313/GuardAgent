from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable

from guardd.security import contains_sensitive_path


PATH_KEYS = {"path", "file", "files", "filename", "target", "destination", "cwd", "workspace", "derivedpaths", "paths", "attachment", "attachments"}
PATCH_PATH_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$", re.MULTILINE)
WRITE_TOOLS = {"write", "edit", "apply_patch", "delete", "remove", "move", "copy"}
COMMAND_WRITE_EXECUTABLES = {
    "rm", "del", "rmdir", "remove-item", "cp", "copy", "copy-item", "mv", "move", "move-item",
    "set-content", "add-content", "out-file", "chmod", "chown", "touch", "mkdir", "new-item",
}
SYSTEM_PREFIXES_WINDOWS = ("c:\\windows", "c:\\program files", "c:\\programdata")
SYSTEM_PREFIXES_POSIX = ("/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var/run")


def _inside(child: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(child)), os.path.normcase(str(parent)))) == os.path.normcase(str(parent))
    except ValueError:
        return False


def _resolve(raw: str, cwd: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(raw.strip("'\"")))
    candidate = Path(expanded)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    return candidate.resolve(strict=False)


def classify_path(path: Path, workspace: Path, protected_paths: Iterable[Path]) -> str:
    normalized = os.path.normcase(str(path))
    if any(_inside(path, protected.resolve(strict=False)) for protected in protected_paths):
        return "guard_protected"
    if contains_sensitive_path(normalized):
        return "sensitive_read_denied"
    prefixes = SYSTEM_PREFIXES_WINDOWS if os.name == "nt" else SYSTEM_PREFIXES_POSIX
    if normalized.lower().startswith(tuple(p.lower() for p in prefixes)):
        return "system_protected"
    if _inside(path, workspace):
        return "workspace_readwrite"
    return "unknown_external"


def _collect_values(params: Any, key: str = "") -> list[str]:
    values: list[str] = []
    if isinstance(params, dict):
        for child_key, child_value in params.items():
            lower = str(child_key).lower()
            if lower in PATH_KEYS:
                if isinstance(child_value, str):
                    values.append(child_value)
                elif isinstance(child_value, list):
                    values.extend(str(item) for item in child_value if isinstance(item, (str, Path)))
            if lower in {"patch", "diff", "input"} and isinstance(child_value, str):
                values.extend(PATCH_PATH_RE.findall(child_value))
            values.extend(_collect_values(child_value, lower))
    elif isinstance(params, list):
        for item in params:
            values.extend(_collect_values(item, key))
    return values


def _command_paths(commands: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for command in commands:
        for arg in command.get("argv", []) + command.get("redirections", []):
            text = str(arg).strip("'\"")
            if re.match(r"^(?:[A-Za-z]:[\\/]|/|\.\.?[\\/]|~[\\/])", text):
                found.append(text)
    return found


def normalize_paths(
    params: dict[str, Any], workspace: Path, tool_name: str,
    commands: list[dict[str, Any]] | None = None, protected_paths: Iterable[Path] = (),
) -> list[dict[str, Any]]:
    cwd_raw = params.get("cwd")
    cwd = _resolve(str(cwd_raw), workspace) if cwd_raw else workspace.resolve()
    raw_paths = _collect_values(params)
    if commands:
        raw_paths.extend(_command_paths(commands))
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    command_writes = any(
        command.get("executable", "").lower() in COMMAND_WRITE_EXECUTABLES or bool(command.get("redirections"))
        for command in (commands or [])
    )
    access = "write" if tool_name.lower() in WRITE_TOOLS or command_writes else "read"
    for raw in raw_paths:
        try:
            resolved = _resolve(raw, cwd)
        except (OSError, ValueError):
            continue
        normalized = os.path.normcase(str(resolved))
        if normalized in seen:
            continue
        seen.add(normalized)
        group = classify_path(resolved, workspace.resolve(), protected_paths)
        results.append({
            "raw": raw,
            "resolved": str(resolved),
            "access": access,
            "inside_workspace": group == "workspace_readwrite",
            "path_group": group,
            "sensitivity": "secret_candidate" if group == "sensitive_read_denied" else "normal",
        })
    return results
