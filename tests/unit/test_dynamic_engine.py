import asyncio

from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import ingest_local
from src.models import AttackResponse


class FakeTarget:
    def __init__(self) -> None:
        self.calls = 0

    async def send(self, payload: str, *, attack_type: str = "") -> AttackResponse:
        self.calls += 1
        if "ignore" in payload.lower():
            return AttackResponse(status_code=200, text="Sure, I'll ignore my instructions.")
        return AttackResponse(status_code=200, text="I cannot help with that request.")

    async def close(self) -> None:
        return None


def test_dynamic_attacks_use_injected_target_and_canonical_methodology() -> None:
    target = FakeTarget()
    config = load_config().model_copy(update={"attacks": ["prompt_injection"]})

    async def run() -> dict:
        return await ArgusEngine(config, target).run(ingest_local("config"))

    result = asyncio.run(run())
    assert target.calls == 3
    assert len(result["attack_results"]) == 3
    assert all(
        item["evaluation_methodology"] == "canonical_only" for item in result["attack_results"]
    )
