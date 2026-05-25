"""
BaseStaticScanner — every static scanner must implement this interface.
"""
from abc import ABC, abstractmethod
from typing import List


class BaseStaticScanner(ABC):
    scanner_id: str

    @abstractmethod
    def scan(self, context) -> List[dict]:
        """
        Accepts a normalized ScanContext.
        Returns structured Finding objects.
        Must be deterministic — no stochastic calls.
        """
        ...
