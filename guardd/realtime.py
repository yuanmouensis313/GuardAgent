from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class StreamEvent:
    event_id: int
    event_type: str
    data: dict[str, Any]
    created_at: str

    def encode(self) -> str:
        payload = {**self.data, "server_time": self.created_at}
        return f"id: {self.event_id}\nevent: {self.event_type}\ndata: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"


class EventBus:
    """Small in-memory replay buffer used by the local UI SSE stream."""

    def __init__(self, max_events: int = 256):
        self._events: deque[StreamEvent] = deque(maxlen=max_events)
        self._sequence = 0
        self._lock = threading.RLock()

    def publish(self, event_type: str, data: dict[str, Any] | None = None) -> StreamEvent:
        with self._lock:
            self._sequence += 1
            event = StreamEvent(
                event_id=self._sequence,
                event_type=event_type,
                data=data or {},
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._events.append(event)
            return event

    def after(self, event_id: int) -> list[StreamEvent]:
        with self._lock:
            return [event for event in self._events if event.event_id > event_id]

    @property
    def latest_id(self) -> int:
        with self._lock:
            return self._sequence
