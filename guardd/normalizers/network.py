from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit


URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>]+", re.IGNORECASE)
_DNS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="guard-dns")
_DNS_SLOTS = threading.BoundedSemaphore(8)
_DNS_CACHE: dict[str, tuple[float, list[str] | None]] = {}
_DNS_LOCK = threading.Lock()


def _resolve(host: str) -> list[str] | None:
    with _DNS_LOCK:
        cached = _DNS_CACHE.get(host)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        _DNS_CACHE.pop(host, None)
    if not _DNS_SLOTS.acquire(blocking=False):
        return None
    future = _DNS_EXECUTOR.submit(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    future.add_done_callback(lambda _: _DNS_SLOTS.release())
    try:
        rows = future.result(timeout=0.05)
        addresses = sorted({row[4][0] for row in rows})
        result = addresses or None
    except (TimeoutError, OSError, socket.gaierror):
        result = None
    with _DNS_LOCK:
        if len(_DNS_CACHE) >= 1024:
            _DNS_CACHE.pop(next(iter(_DNS_CACHE)))
        _DNS_CACHE[host] = (time.monotonic() + (60 if result else 5), result)
    return result


def _classify(host: str, allowlist: set[str], denylist: set[str], resolve_dns: bool) -> tuple[str, list[str]]:
    lower = host.rstrip(".").lower()
    if lower in denylist or any(lower.endswith("." + item) for item in denylist):
        return "denied", []
    if lower in {"localhost", "localhost.localdomain"}:
        return "loopback", ["127.0.0.1"]
    try:
        address = ipaddress.ip_address(lower.strip("[]"))
        if address.is_loopback:
            return "loopback", [str(address)]
        if address.is_private or address.is_link_local:
            return "private", [str(address)]
        return "direct_ip", [str(address)]
    except ValueError:
        pass
    base = "approved_public" if lower in allowlist or any(lower.endswith("." + item) for item in allowlist) else "new_public"
    if not resolve_dns:
        return base, []
    addresses = _resolve(lower)
    if not addresses:
        return "unresolved", []
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.is_private or address.is_loopback or address.is_link_local:
            return "dns_private", addresses
    return base, addresses


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def normalize_network_targets(params: dict[str, Any], allowlist: Iterable[str] = (), denylist: Iterable[str] = (), resolve_dns: bool = True) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    method = str(params.get("method", "GET")).upper()
    joined = " ".join(_walk_strings(params)).lower()
    command_upload = bool(re.search(r"(?:curl|wget|invoke-restmethod|invoke-webrequest).*(?:\s(?:-d|--data|--data-binary|-f|--form|-t|--upload-file|-method)\b|\s-x\s*(?:post|put|patch|delete)\b)", joined, re.IGNORECASE))
    direction = "outbound_write" if method in {"POST", "PUT", "PATCH", "DELETE"} or any(k in params for k in ("body", "data", "files", "attachment")) or command_upload else "outbound_read"
    for text in _walk_strings(params):
        for match in URL_RE.findall(text):
            try:
                split = urlsplit(match.rstrip(".,);]"))
                host = split.hostname or ""
                port = split.port
            except ValueError:
                targets.append({"scheme": "unknown", "host": "", "port": None, "direction": direction, "classification": "invalid", "resolved_ips": [], "sanitized_url": "<invalid-url>"})
                continue
            if not host:
                continue
            key = (split.scheme.lower(), host.lower(), port)
            if key in seen:
                continue
            seen.add(key)
            clean_url = urlunsplit((split.scheme, split.hostname or "", split.path, "<redacted>" if split.query else "", ""))
            classification, resolved_ips = _classify(host, {x.lower() for x in allowlist}, {x.lower() for x in denylist}, resolve_dns)
            targets.append({
                "scheme": split.scheme.lower(), "host": host.lower(), "port": port,
                "direction": direction, "classification": classification, "resolved_ips": resolved_ips,
                "sanitized_url": clean_url,
            })
    return targets
