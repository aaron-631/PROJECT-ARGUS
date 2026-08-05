"""Validated domain models used throughout Argus.

The JSON files next to this module are intentionally kept as public contracts;
the Pydantic models are the runtime representation of those same contracts.
"""

from .domain import (
    AttackResult,
    AttackProbe,
    AttackResponse,
    EvaluationResult,
    FileRecord,
    Finding,
    JudgeDecision,
    ReportMetadata,
    ScanContext,
    ScanReport,
    Severity,
    SEVERITY_ORDER,
    SourceMetadata,
)
from .documents import DocumentKind, ParsedDocument

__all__ = [
    "AttackProbe",
    "AttackResponse",
    "AttackResult",
    "DocumentKind",
    "EvaluationResult",
    "FileRecord",
    "Finding",
    "JudgeDecision",
    "ReportMetadata",
    "ParsedDocument",
    "ScanContext",
    "ScanReport",
    "Severity",
    "SEVERITY_ORDER",
    "SourceMetadata",
]
