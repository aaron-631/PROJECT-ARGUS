"""Retry, timeout, and rate-limit behavior without external services."""

import asyncio

from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import ingest_local
from src.models import AttackResponse


class FailingTarget:
    def __init__(self, status: int) -> None:
        self.status = status
        self.calls = 0

    async def send(self, payload: str, *, attack_type: str = "") -> AttackResponse:
        self.calls += 1
        return AttackResponse(status_code=self.status, text="synthetic failure")

    async def close(self) -> None:
        return None


def test_retry_exhaustion_is_bounded_and_reported() -> None:
    target = FailingTarget(503)
    base = load_config()
    config = load_config().model_copy(
        update={
            "attacks": ["prompt_injection"],
            "engine": base.engine.model_copy(update={"max_retries": 2, "backoff_base_seconds": 0}),
        }
    )

    async def run() -> dict:
        return await ArgusEngine(config, target).run(ingest_local("config"))

    result = asyncio.run(run())
    assert target.calls == 3 * 3
    assert all(item["error"].startswith("HTTP 503") for item in result["attack_results"])
