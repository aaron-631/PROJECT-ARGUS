import asyncio

from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import ingest_local
from src.interfaces.attack import BaseAttackModule
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


class StreamOnlyFixtureAttack(BaseAttackModule):
    module_id = "stream_only_fixture"
    version = "1.0.0"
    attack_type = "prompt_injection"

    async def probe_stream(self, target_endpoint: str | None = None):
        del target_endpoint
        yield {"payload_id": "STREAM-001", "payload": "fixture payload"}


def test_dynamic_attacks_use_injected_target_and_canonical_methodology() -> None:
    target = FakeTarget()
    config = load_config().model_copy(update={"attacks": ["prompt_injection"]})

    async def run() -> dict:
        return await ArgusEngine(config, target).run(ingest_local("config"))

    result = asyncio.run(run())
    assert target.calls == 12
    assert len(result["attack_results"]) == 12
    assert all(
        item["evaluation_methodology"] == "canonical_only" for item in result["attack_results"]
    )


def test_entry_point_style_stream_only_attack_is_executed(monkeypatch) -> None:
    import src.core.engine as engine_module

    original_get_enabled_modules = engine_module.get_enabled_modules

    def enabled_modules(config):
        registry = original_get_enabled_modules(config)
        registry["attack_modules"] = {"stream_only_fixture": StreamOnlyFixtureAttack}
        return registry

    monkeypatch.setattr(
        engine_module,
        "get_enabled_modules",
        enabled_modules,
    )
    target = FakeTarget()
    config = load_config().model_copy(update={"attacks": ["prompt_injection"]})

    async def run() -> dict:
        return await ArgusEngine(config, target).run(ingest_local("config"))

    result = asyncio.run(run())
    assert len(result["attack_results"]) == 1
    assert result["attack_results"][0]["payload_id"] == "STREAM-001"
