"""Async token-bucket limiter with bounded, monotonic waits."""

from __future__ import annotations

import asyncio
from email.utils import parsedate_to_datetime
import time


class TokenBucketRateLimiter:
    def __init__(self, rate_per_second: float, capacity: int | None = None) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = float(rate_per_second)
        self.capacity = float(capacity or max(1, int(rate_per_second)))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait_for = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_for)

    def penalize(self, seconds: float) -> None:
        """Delay the next token after a provider throttle response."""
        if seconds > 0:
            self.tokens = 0.0
            self.updated = max(self.updated, time.monotonic() + seconds)


def parse_retry_after(value: str | None) -> float:
    """Parse both the HTTP delta-seconds and HTTP-date Retry-After forms."""

    if not value:
        return 0.0
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            delay = parsedate_to_datetime(value).timestamp() - time.time()
            return max(0.0, delay)
        except (TypeError, ValueError, OverflowError):
            return 0.0


__all__ = ["TokenBucketRateLimiter", "parse_retry_after"]
