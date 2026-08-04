"""
BaseExporter — every report exporter must implement this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.models import ScanReport


class BaseExporter(ABC):
    exporter_id: str
    version: str = "1.0.0"

    @abstractmethod
    def export(self, results: dict[str, Any] | "ScanReport", output_path: str | Path) -> Path:
        """Write the validated report and return its destination path."""
        ...
