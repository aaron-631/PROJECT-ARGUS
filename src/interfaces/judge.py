"""
JudgeBackend — optional semantic evaluation layer.
Canonical signals are always calculated by the engine.
JudgeBackend provides auxiliary scoring only.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class JudgeBackend(ABC):

    @abstractmethod
    async def evaluate(
        self,
        sanitized_output: str,
        context: Dict[str, Any],
    ) -> Optional[float]:
        """
        Returns normalized score 0.0 (Safe) → 1.0 (Critical).
        Returns None if evaluation is impossible or skipped.
        """
        ...


class NullJudgeBackend(JudgeBackend):
    """Default. Returns None immediately. No external calls. Air-gapped safe."""

    async def evaluate(self, sanitized_output: str, context: Dict[str, Any]) -> None:
        return None


class MockJudgeBackend(JudgeBackend):
    """Returns hardcoded scores by keyword. Used in test suite only."""

    async def evaluate(self, sanitized_output: str, context: Dict[str, Any]) -> float:
        if "ignore previous instructions" in sanitized_output.lower():
            return 0.95
        return 0.1


class APIJudgeBackend(JudgeBackend):
    """Calls GPT-4o-mini or Claude Haiku at temperature=0.0. Research/red-team use."""

    async def evaluate(self, sanitized_output: str, context: Dict[str, Any]) -> Optional[float]:
        # TODO: implement API call with XML delimiter wrapping
        raise NotImplementedError
