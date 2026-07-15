from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from pathlib import Path
from urllib.parse import urlsplit


def response(decision: str, reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"protocolVersion": 1, "decision": decision}
    if reason:
        result["reason"] = reason[:512]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="OpenClaw protocol mode")
    parser.parse_args()
    try:
        request = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(json.dumps(response("block", f"invalid JSON: {exc}")))
        return 2
    if request.get("protocolVersion") != 1:
        print(json.dumps(response("block", "unsupported install policy protocol")))
        return 2
    target_type = request.get("targetType")
    target_name = str(request.get("targetName", ""))
    if target_type not in {"skill", "plugin"} or not target_name:
        print(json.dumps(response("block", "missing or unsupported install target")))
        return 2
    allowlist = {item.strip() for item in os.getenv("GUARD_INSTALL_ALLOWLIST", "").split(",") if item.strip()}
    if target_name not in allowlist:
        print(json.dumps(response("block", f"{target_type} {target_name!r} is not in GUARD_INSTALL_ALLOWLIST")))
        return 0
    source = request.get("source") or {}
    source_kind = str(source.get("kind", ""))
    requested = str((request.get("request") or {}).get("requestedSpecifier", ""))
    mutable = source.get("mutable") is True
    network = source.get("network") is True
    if network:
        origin = request.get("origin") or {}
        registry = str(origin.get("registry", ""))
        registry_host = (urlsplit(registry).hostname or "").lower()
        allowed_registries = {item.strip().lower() for item in os.getenv("GUARD_INSTALL_REGISTRIES", "").split(",") if item.strip()}
        exact_version = bool(re.search(r"@\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$", requested))
        if source_kind not in {"npm", "clawhub"} or mutable or not exact_version or registry_host not in allowed_registries:
            print(json.dumps(response("block", "network installs require an approved registry, immutable source, and exact version")))
            return 0
    else:
        source_path = Path(str(request.get("sourcePath", ""))).resolve(strict=False)
        allowed_roots = [Path(item).expanduser().resolve(strict=False) for item in os.getenv("GUARD_INSTALL_LOCAL_ROOTS", "").split(os.pathsep) if item]
        if source_kind != "local-path" or not any(source_path == root or root in source_path.parents for root in allowed_roots):
            print(json.dumps(response("block", "local install source is outside GUARD_INSTALL_LOCAL_ROOTS")))
            return 0
    print(json.dumps(response("allow")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
