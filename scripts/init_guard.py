from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardd.config import Settings
from guardd.policy import PolicyLoader
from guardd.security import ensure_token


def main() -> None:
    settings = Settings.from_env()
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    token = ensure_token(settings.token_path)
    policy = PolicyLoader().load(settings.policy_path)
    try:
        os.chmod(settings.state_dir, 0o700)
        os.chmod(settings.token_path, 0o600)
    except OSError:
        pass
    print(json.dumps({
        "state_dir": str(settings.state_dir),
        "token_file": str(settings.token_path),
        "token_length": len(token),
        "policy": str(settings.policy_path),
        "policy_digest": policy.digest,
        "mode": policy.mode,
        "next": "Start guardd, then run guardctl doctor before enabling OpenClaw",
    }, indent=2))


if __name__ == "__main__":
    main()
