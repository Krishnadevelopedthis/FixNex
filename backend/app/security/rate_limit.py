"""Small dependency-free sliding-window rate limiter for auth endpoints."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from app.core.config import settings
from app.core.exceptions import RateLimitedError


class SlidingWindowRateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_attempts:
                retry_in = int(self.window_seconds - (now - bucket[0])) + 1
                raise RateLimitedError(
                    f"Too many attempts. Try again in {retry_in} seconds."
                )
            bucket.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


login_rate_limiter = SlidingWindowRateLimiter(
    settings.AUTH_RATE_LIMIT_ATTEMPTS,
    settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
)
