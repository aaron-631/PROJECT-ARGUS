"""
Prompt Injection Attack Module — V1 implementation placeholder.
"""
from src.interfaces.attack import BaseAttackModule
from src.core.registry import register_attack_module


@register_attack_module
class PromptInjectionModule(BaseAttackModule):
    module_id = "prompt_injection"
    version = "0.1.0"

    async def probe_stream(self, target_endpoint: str):
        # TODO: Week 5-6 — load payloads from data/attacks/prompt_injection/
        raise NotImplementedError

    def evaluate_canonical(self, response: str) -> dict:
        # TODO: deterministic regex + signature matching
        raise NotImplementedError
