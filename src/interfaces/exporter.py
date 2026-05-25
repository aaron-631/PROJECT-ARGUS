"""
BaseExporter — every report exporter must implement this interface.
"""
from abc import ABC, abstractmethod


class BaseExporter(ABC):

    @abstractmethod
    def export(self, results: dict, output_path: str) -> None:
        ...
