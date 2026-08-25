from __future__ import annotations

import threading
import time


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, cooldown_seconds: int = 60):
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(1, cooldown_seconds)
        self._failures = 0
        self._open_until = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._open_until <= time.monotonic():
                if self._open_until:
                    self._open_until = 0.0
                    self._failures = 0
                return True
            return False

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._open_until = 0.0

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._open_until = time.monotonic() + self.cooldown_seconds

    def status(self) -> dict[str, int | bool]:
        with self._lock:
            remaining = max(0, int(self._open_until - time.monotonic()))
            return {
                "open": remaining > 0,
                "consecutive_failures": self._failures,
                "cooldown_remaining_seconds": remaining,
            }
