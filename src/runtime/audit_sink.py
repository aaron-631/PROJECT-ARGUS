"""Retrying remote audit delivery for the runtime gateway."""

from __future__ import annotations

import asyncio
import os
from typing import Any

import aiohttp


class AuditSink:
    """Send already-sanitized audit records to a durable collector."""

    def __init__(
        self,
        url: str,
        token_env: str,
        timeout_seconds: float,
        max_retries: int,
    ) -> None:
        self.url = url
        self.token_env = token_env
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    async def publish(self, session: aiohttp.ClientSession, record: dict[str, Any]) -> bool:
        headers = {"Content-Type": "application/json"}
        token = os.getenv(self.token_env)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for attempt in range(self.max_retries + 1):
            try:
                async with session.post(
                    self.url,
                    json=record,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                ) as response:
                    if 200 <= response.status < 300:
                        return True
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            if attempt < self.max_retries:
                await asyncio.sleep(min(2.0, 0.1 * (2**attempt)))
        return False


__all__ = ["AuditSink"]
