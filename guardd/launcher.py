from __future__ import annotations

import socket
import sys
from collections.abc import Callable
from enum import Enum

import httpx

from guardd.bootstrap import initialize
from guardd.config import Settings
from guardd.main import run


class ServiceProbe(str, Enum):
    AVAILABLE = "available"
    GUARDAGENT = "guardagent"
    OCCUPIED = "occupied"


def _base_url(settings: Settings) -> str:
    host = f"[{settings.host}]" if ":" in settings.host else settings.host
    return f"http://{host}:{settings.port}"


def _port_is_available(settings: Settings) -> bool:
    addresses = socket.getaddrinfo(
        settings.host,
        settings.port,
        type=socket.SOCK_STREAM,
    )
    for family, socktype, protocol, _, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as candidate:
                candidate.bind(address)
            return True
        except OSError:
            continue
    return False


def probe_service(settings: Settings, timeout: float = 0.35) -> ServiceProbe:
    if _port_is_available(settings):
        return ServiceProbe.AVAILABLE
    try:
        with httpx.Client(timeout=timeout, trust_env=False) as client:
            response = client.get(f"{_base_url(settings)}/v1/health")
    except httpx.ConnectError:
        return ServiceProbe.AVAILABLE
    except httpx.HTTPError:
        return ServiceProbe.OCCUPIED

    try:
        payload = response.json()
    except ValueError:
        return ServiceProbe.OCCUPIED
    if (
        response.status_code == 200
        and isinstance(payload, dict)
        and payload.get("status") == "ok"
        and payload.get("schema_version") == "1.0"
    ):
        return ServiceProbe.GUARDAGENT
    return ServiceProbe.OCCUPIED


def launch(
    settings: Settings | None = None,
    service_runner: Callable[[Settings | None], None] = run,
) -> int:
    settings = settings or Settings.from_env()
    policy = initialize(settings)
    base_url = _base_url(settings)
    probe = probe_service(settings)

    if probe is ServiceProbe.GUARDAGENT:
        print(f"GuardAgent is already running at {base_url}")
        print("Open securely: uv run guardctl ui")
        return 0
    if probe is ServiceProbe.OCCUPIED:
        raise RuntimeError(
            f"{settings.host}:{settings.port} is already in use by another service; "
            "set GUARDD_PORT to an available loopback port"
        )

    print("GuardAgent development server")
    print(f"Service: {base_url}")
    print(f"Console: {base_url}/ui/")
    print(f"Policy: {policy.source} ({policy.mode}, {policy.digest})")
    print(f"State: {settings.state_dir}")
    print("Open securely in another terminal: uv run guardctl ui")
    print("Press Ctrl+C to stop.")
    service_runner(settings)
    return 0


def main() -> None:
    try:
        status = launch()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"GuardAgent failed to start: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    raise SystemExit(status)


if __name__ == "__main__":
    main()
