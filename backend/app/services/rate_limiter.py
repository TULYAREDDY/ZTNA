"""Simple fixed-window in-memory rate limiter."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class FixedWindowRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, *, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        with self._lock:
            q = self._events[key]
            while q and (now - q[0]) > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


rate_limiter = FixedWindowRateLimiter()
