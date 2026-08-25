from __future__ import annotations

import os

from guardd.config import Settings
from guardd.policy import PolicyLoader
from guardd.policy.loader import LoadedPolicy
from guardd.security import ensure_hmac_key, ensure_token


def initialize(settings: Settings) -> LoadedPolicy:
    """Validate configuration and idempotently initialize local service state."""
    policy = PolicyLoader().load(settings.policy_path)

    settings.state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(settings.state_dir, 0o700)
    except OSError:
        pass

    ensure_token(settings.token_path)
    ensure_token(settings.security_override_token_path)
    ensure_hmac_key(settings.hmac_key_path)

    for path in (
        settings.token_path,
        settings.security_override_token_path,
        settings.hmac_key_path,
    ):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    return policy
