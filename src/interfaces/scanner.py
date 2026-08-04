"""
BaseStaticScanner — every static scanner must implement this interface.
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.models import Finding, ScanContext


class BaseStaticScanner(ABC):
    scanner_id: str
    version: str = "1.0.0"
    supported_extensions: ClassVar[frozenset[str]] = frozenset()
    supported_document_kinds: ClassVar[frozenset[str]] = frozenset()
    rule_capabilities: ClassVar[Mapping[str, object]] = {}

    @abstractmethod
    def scan(self, context: "ScanContext") -> list["Finding"]:
        """
        Accepts a normalized ScanContext.
        Returns structured Finding objects.
        Must be deterministic — no stochastic calls.
        """
        ...
