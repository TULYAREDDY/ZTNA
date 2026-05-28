"""Async pub/sub bus that fan-outs events to WebSocket subscribers.

Used by the API layer to broadcast posture / access / revoke events in
real-time to the React dashboard. Also keeps a bounded ring-buffer so
late-joining clients can backfill recent activity.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Deque, Set

from app.models.schemas import EventView


class EventBus:
    def __init__(self, history_size: int = 500) -> None:
        self._subscribers: Set[asyncio.Queue[EventView]] = set()
        self._history: Deque[EventView] = deque(maxlen=history_size)
        self._lock = asyncio.Lock()

    async def publish(self, event: EventView) -> None:
        async with self._lock:
            self._history.append(event)
            dead: list[asyncio.Queue[EventView]] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.discard(q)

    async def subscribe(self) -> asyncio.Queue[EventView]:
        q: asyncio.Queue[EventView] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[EventView]) -> None:
        async with self._lock:
            self._subscribers.discard(q)

    def history(self, limit: int = 100) -> list[EventView]:
        return list(self._history)[-limit:]


bus = EventBus()
