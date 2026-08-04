"""
BaseAttackModule — every attack module must implement this interface.
"""

from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, TYPE_CHECKING

if TYPE_CHECKING:
    from src.models import AttackProbe


class BaseAttackModule(ABC):
    module_id: str
    version: str

    @abstractmethod
    def probe_stream(
        self, target_endpoint: str | None = None
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Yields attack probes to be sent to the target."""
        ...

    @abstractmethod
    def evaluate_canonical(self, response: str) -> dict[str, Any]:
        """Deterministic result scoring — no external calls."""
        ...

    def probes(self) -> list["AttackProbe"]:
        """Optional synchronous dataset access used by injected target clients."""
        return []
