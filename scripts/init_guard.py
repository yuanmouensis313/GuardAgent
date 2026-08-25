from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardd.bootstrap import initialize
from guardd.config import Settings


def main() -> None:
    settings = Settings.from_env()
    policy = initialize(settings)
    print(json.dumps({
        "state_dir": str(settings.state_dir),
        "token_file": str(settings.token_path),
        "token_length": len(settings.token_path.read_text(encoding="utf-8").strip()),
        "security_override_token_file": str(settings.security_override_token_path),
        "security_override_token_length": len(
            settings.security_override_token_path.read_text(encoding="utf-8").strip()
        ),
        "hmac_key_file": str(settings.hmac_key_path),
        "policy": str(settings.policy_path),
        "policy_digest": policy.digest,
        "mode": policy.mode,
        "next": "Run uv run guardagent (or guardd), then run guardctl doctor before enabling OpenClaw",
    }, indent=2))


if __name__ == "__main__":
    main()
