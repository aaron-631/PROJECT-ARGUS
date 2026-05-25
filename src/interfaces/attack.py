"""
BaseAttackModule — every attack module must implement this interface.
"""
from abc import ABC, abstractmethod
from typing import AsyncGenerator


class BaseAttackModule(ABC):
    module_id: str
    version: str

    @abstractmethod
    async def probe_stream(self, target_endpoint: str) -> AsyncGenerator[dict, None]:
        """Yields attack probes to be sent to the target."""
        ...

    @abstractmethod
    def evaluate_canonical(self, response: str) -> dict:
        """Deterministic result scoring — no external calls."""
        ...
