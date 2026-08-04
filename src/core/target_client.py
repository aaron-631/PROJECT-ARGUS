"""Authorized live-target adapters used by dynamic attack modules.

Argus deliberately uses HTTP instead of vendor SDKs.  That keeps the scanner
portable across hosted providers, OpenAI-compatible gateways, and local models.
The adapter only reads credentials from the environment and never puts them in
reports or attack payloads.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Protocol
from urllib.parse import urlparse

from src.models import AttackResponse
from src.models.config import TargetConfig


class TargetClient(Protocol):
    async def send(self, payload: str, *, attack_type: str = "") -> AttackResponse:
        """Send one attack payload and return a normalized response."""
        ...

    async def close(self) -> None:
        """Release transport resources."""
        ...


_DEFAULT_API_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
_AUTH_HEADER = {
    "openai": "Authorization",
    "anthropic": "x-api-key",
    "generic": "Authorization",
}


def resolve_api_key(target: TargetConfig) -> str | None:
    """Read the provider key from an explicitly configured or standard env var."""

    environment_name = target.api_key_env or _DEFAULT_API_KEY_ENV.get(target.provider)
    return os.getenv(environment_name) if environment_name else None


class HTTPTargetClient:
    """HTTP client for generic, OpenAI-compatible, Anthropic, and Ollama APIs.

    ``generic`` preserves Argus' small test-server contract.  ``openai`` also
    works with most self-hosted OpenAI-compatible gateways, which is the most
    common integration boundary for company agents.  Provider-specific fields
    are limited to request formatting; response extraction remains permissive
    enough for common proxy wrappers.
    """

    def __init__(
        self,
        endpoint: str,
        timeout_seconds: float = 30.0,
        headers: dict[str, str] | None = None,
        *,
        target: TargetConfig | None = None,
        provider: str = "generic",
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.target = target or TargetConfig.model_validate({"provider": provider, "model": model})
        self.provider = self.target.provider
        self.model = self.target.model
        if self.provider != "generic" and not self.model:
            raise ValueError(f"target model is required for provider '{self.provider}'")
        self.headers = self._build_headers(headers or {}, api_key)
        self._session: Any = None

    def _build_headers(self, extra: dict[str, str], api_key: str | None) -> dict[str, str]:
        headers = {"Content-Type": "application/json", **self.target.headers, **extra}
        for name, environment_name in self.target.header_env.items():
            value = os.getenv(environment_name)
            if value:
                headers[name] = value
        if api_key:
            auth_header = self.target.auth_header or _AUTH_HEADER.get(self.provider)
            if auth_header:
                if auth_header.lower() == "authorization":
                    headers.setdefault(auth_header, f"Bearer {api_key}")
                else:
                    headers.setdefault(auth_header, api_key)
        if self.provider == "anthropic":
            headers.setdefault("anthropic-version", "2023-06-01")
        return headers

    def _build_body(self, payload: str, attack_type: str) -> dict[str, Any]:
        messages = [{"role": "user", "content": payload}]
        if self.provider == "openai":
            if urlparse(self.endpoint).path.rstrip("/").endswith("/responses"):
                return {
                    "model": self.model,
                    "input": payload,
                    "temperature": self.target.temperature,
                    "max_output_tokens": self.target.max_tokens,
                }
            return {
                "model": self.model,
                "messages": messages,
                "temperature": self.target.temperature,
                "max_tokens": self.target.max_tokens,
            }
        if self.provider == "anthropic":
            return {
                "model": self.model,
                "max_tokens": self.target.max_tokens,
                "temperature": self.target.temperature,
                "messages": messages,
            }
        if self.provider == "ollama":
            return {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": self.target.temperature,
                    "num_predict": self.target.max_tokens,
                },
            }
        return {"messages": messages, "attack_type": attack_type}

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
        body = self._build_body(payload, attack_type)
        async with self._session.post(self.endpoint, json=body, headers=self.headers) as response:
            raw = await response.text()
            return AttackResponse(
                status_code=response.status,
                text=_extract_response_text(raw),
                headers={str(key): str(value) for key, value in response.headers.items()},
                latency_ms=(time.perf_counter() - started) * 1000,
            )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None


def _content_to_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [_content_to_text(item) for item in value]
        text = " ".join(part for part in parts if part)
        return text or None
    if isinstance(value, dict):
        for key in ("text", "content", "output_text", "response"):
            if key in value:
                result = _content_to_text(value[key])
                if result:
                    return result
    return None


def _extract_response_text(raw: str) -> str:
    """Extract text from common model responses, preserving unknown JSON safely."""

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if isinstance(data, dict):
        direct = _content_to_text(data.get("output_text"))
        if direct:
            return direct
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            choice = choices[0]
            if isinstance(choice, dict):
                message = choice.get("message")
                result = _content_to_text(message) or _content_to_text(choice.get("text"))
                if result:
                    return result
        for key in ("content", "response", "message", "output", "result"):
            result = _content_to_text(data.get(key))
            if result:
                return result
    return raw


__all__ = ["HTTPTargetClient", "TargetClient", "_extract_response_text", "resolve_api_key"]
