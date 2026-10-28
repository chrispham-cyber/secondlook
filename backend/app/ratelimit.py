"""Small in-memory sliding-window rate limiter (per client IP). Good enough for one instance;
swap for Redis when running more than one backend replica."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        window = self._hits[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.per_minute:
            return False, max(1, int(60 - (now - window[0])) + 1)
        window.append(now)
        if len(self._hits) > 10_000:  # bound memory: drop idle clients
            for k in [k for k, v in self._hits.items() if not v][:5000]:
                del self._hits[k]
        return True, 0
