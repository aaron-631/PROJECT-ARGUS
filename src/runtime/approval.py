"""Provider-neutral HTTP client for human approval decisions."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any

import aiohttp

from .policy import approval_context


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    decision_id: str | None = None
    reason_code: str = "APPROVAL_SERVICE_DENIED"


class ApprovalClient:
    """Call an external approval service without sending prompts or raw secrets."""

    def __init__(
        self, url: str, token_env: str, timeout_seconds: float, max_response_bytes: int = 1_048_576
    ) -> None:
        self.url = url
        self.token_env = token_env
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    async def authorize(
        self,
        session: aiohttp.ClientSession,
        request_id: str,
        body: dict[str, Any],
        reason_codes: list[str],
    ) -> ApprovalResult:
        headers = {"Content-Type": "application/json", "X-Request-ID": request_id}
        token = os.getenv(self.token_env)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload = {
            "request_id": request_id,
            "reason_codes": reason_codes,
            "tools": approval_context(body),
        }
        try:
            async with session.post(
                self.url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
            ) as response:
                if response.status < 200 or response.status >= 300:
                    return ApprovalResult(False, reason_code="APPROVAL_SERVICE_DENIED")
                content = getattr(response, "content", None)
                if content is not None and callable(getattr(content, "read", None)):
                    raw = await content.read(self.max_response_bytes + 1)
                elif callable(getattr(response, "text", None)):
                    raw = (await response.text()).encode("utf-8")
                else:
                    raw = json.dumps(await response.json()).encode("utf-8")
                if len(raw) > self.max_response_bytes:
                    return ApprovalResult(False, reason_code="APPROVAL_SERVICE_UNAVAILABLE")
                result = json.loads(raw.decode("utf-8"))
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError, ValueError):
            return ApprovalResult(False, reason_code="APPROVAL_SERVICE_UNAVAILABLE")
        if not isinstance(result, dict) or result.get("approved") is not True:
            return ApprovalResult(False, reason_code="APPROVAL_SERVICE_DENIED")
        decision_id = result.get("decision_id")
        return ApprovalResult(
            True,
            decision_id=str(decision_id) if decision_id is not None else None,
            reason_code="APPROVED_BY_SERVICE",
        )


__all__ = ["ApprovalClient", "ApprovalResult"]
