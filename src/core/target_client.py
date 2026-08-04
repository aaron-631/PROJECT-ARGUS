"""Target endpoint abstraction used by dynamic attack modules."""

from __future__ import annotations

import time
from typing import Any, Protocol

from src.models import AttackResponse


class TargetClient(Protocol):
    async def send(self, payload: str, *, attack_type: str = "") -> AttackResponse:
        """Send one attack payload and return a normalized response."""
        ...

    async def close(self) -> None:
        """Release transport resources."""
        ...


class HTTPTargetClient:
    """Small provider-neutral client for OpenAI/Anthropic-style endpoints."""

    def __init__(
        self, endpoint: str, timeout_seconds: float = 30.0, headers: dict[str, str] | None = None
    ) -> None:
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self._session: Any = None

    async def send(self, payload: str, *, attack_type: str = "") -> AttackResponse:
        try:
            import aiohttp
        except ImportError as exc:
            raise RuntimeError("aiohttp is required for dynamic endpoint execution") from exc
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
            )
        started = time.perf_counter()
        body = {"messages": [{"role": "user", "content": payload}], "attack_type": attack_type}
        async with self._session.post(self.endpoint, json=body, headers=self.headers) as response:
            raw = await response.text()
            text = _extract_response_text(raw)
            return AttackResponse(
                status_code=response.status,
                text=text,
                headers={str(key): str(value) for key, value in response.headers.items()},
                latency_ms=(time.perf_counter() - started) * 1000,
            )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None


def _extract_response_text(raw: str) -> str:
    import json

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if isinstance(data, dict):
        if isinstance(data.get("content"), str):
            return data["content"]
        if isinstance(data.get("content"), list):
            return " ".join(
                str(item.get("text", item)) if isinstance(item, dict) else str(item)
                for item in data["content"]
            )
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message", {})
            return str(message.get("content", choices[0].get("text", "")))
        if isinstance(data.get("response"), str):
            return data["response"]
    return raw


__all__ = ["HTTPTargetClient", "TargetClient"]
