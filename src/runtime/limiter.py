"""Small in-process controls for runtime request admission."""

from __future__ import annotations

from threading import Lock
from time import monotonic


class RuntimeRateLimiter:
    """A bounded token bucket used before a request enters the proxy."""

    def __init__(self, rate_per_second: float, burst: int) -> None:
        self.rate_per_second = rate_per_second
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = monotonic()
        self._lock = Lock()

    def allow(self) -> bool:
        now = monotonic()
        with self._lock:
            elapsed = max(0.0, now - self.updated)
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_second)
            self.updated = now
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True


__all__ = ["RuntimeRateLimiter"]
