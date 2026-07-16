from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


UI_COOKIE_NAME = "guard_ui_session"


class UiAuthError(ValueError):
    pass


@dataclass
class UiSession:
    key: str
    operator: str
    csrf_token: str
    created_at: datetime
    last_seen: datetime
    expires_at: datetime

    def public(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "csrf_token": self.csrf_token,
        }


class UiAuthManager:
    def __init__(self, bootstrap_ttl_seconds: int = 60, idle_minutes: int = 30, absolute_hours: int = 8):
        self.bootstrap_ttl = timedelta(seconds=max(10, bootstrap_ttl_seconds))
        self.idle_ttl = timedelta(minutes=max(1, idle_minutes))
        self.absolute_ttl = timedelta(hours=max(1, absolute_hours))
        self._bootstrap: dict[str, datetime] = {}
        self._sessions: dict[str, UiSession] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _cleanup(self) -> None:
        now = self._now()
        self._bootstrap = {key: expires for key, expires in self._bootstrap.items() if expires > now}
        self._sessions = {
            key: session for key, session in self._sessions.items()
            if session.expires_at > now and session.last_seen + self.idle_ttl > now
        }

    def create_bootstrap(self) -> tuple[str, datetime]:
        code = secrets.token_urlsafe(48)
        expires = self._now() + self.bootstrap_ttl
        with self._lock:
            self._cleanup()
            self._bootstrap[self._digest(code)] = expires
        return code, expires

    def consume_bootstrap(self, code: str) -> tuple[str, UiSession]:
        now = self._now()
        digest = self._digest(code)
        with self._lock:
            self._cleanup()
            expires = self._bootstrap.pop(digest, None)
            if expires is None or expires <= now:
                raise UiAuthError("bootstrap code is invalid, expired, or already used")
            raw_session = secrets.token_urlsafe(48)
            key = self._digest(raw_session)
            session = UiSession(
                key=key,
                operator=f"local-ui:{key[:12]}",
                csrf_token=secrets.token_urlsafe(32),
                created_at=now,
                last_seen=now,
                expires_at=now + self.absolute_ttl,
            )
            self._sessions[key] = session
            return raw_session, session

    def validate(self, raw_session: str | None, *, touch: bool = True, rotate_csrf: bool = False) -> UiSession:
        if not raw_session:
            raise UiAuthError("UI session is missing")
        key = self._digest(raw_session)
        now = self._now()
        with self._lock:
            self._cleanup()
            session = self._sessions.get(key)
            if session is None:
                raise UiAuthError("UI session is invalid or expired")
            if touch:
                session.last_seen = now
            if rotate_csrf:
                session.csrf_token = secrets.token_urlsafe(32)
            return session

    def destroy(self, raw_session: str | None) -> None:
        if not raw_session:
            return
        with self._lock:
            self._sessions.pop(self._digest(raw_session), None)
