"""Canonical static-rule capability contracts and routing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Literal

from src.models.documents import DocumentKind, ParsedDocument

AnalysisMode = Literal["structured", "python_ast", "pattern", "filename"]


@dataclass(frozen=True)
class RuleCapability:
    rule_id: str
    extensions: FrozenSet[str]
    document_kinds: FrozenSet[DocumentKind]
    mode: AnalysisMode

    def supports(self, path: str, document: ParsedDocument | None) -> bool:
        suffix = Path(path).suffix.lower()
        if self.extensions and suffix not in self.extensions and self.mode != "filename":
            return False
        if document is None:
            return self.mode in {"pattern", "filename"}
        if document.parse_error and self.mode in {"structured", "python_ast"}:
            return False
        return document.kind in self.document_kinds


STRUCTURED = frozenset({DocumentKind.JSON, DocumentKind.YAML, DocumentKind.TOML})
TEXT = frozenset({DocumentKind.TEXT})
PYTHON = frozenset({DocumentKind.PYTHON_AST})
ALL = STRUCTURED | TEXT | PYTHON
PATTERN = STRUCTURED | TEXT
CONFIG_EXTENSIONS = frozenset({".json", ".json5", ".yaml", ".yml", ".toml"})


RULE_CAPABILITIES: dict[str, RuleCapability] = {
    "ARGUS_ST_001": RuleCapability("ARGUS_ST_001", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_002": RuleCapability("ARGUS_ST_002", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_003": RuleCapability("ARGUS_ST_003", frozenset({".py"}), PYTHON, "python_ast"),
    "ARGUS_ST_004": RuleCapability("ARGUS_ST_004", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_005": RuleCapability("ARGUS_ST_005", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_006": RuleCapability("ARGUS_ST_006", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_007": RuleCapability("ARGUS_ST_007", frozenset({".py"}), PYTHON, "python_ast"),
    "ARGUS_ST_008": RuleCapability("ARGUS_ST_008", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_009": RuleCapability("ARGUS_ST_009", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_010": RuleCapability("ARGUS_ST_010", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_011": RuleCapability("ARGUS_ST_011", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_012": RuleCapability("ARGUS_ST_012", frozenset(), ALL, "filename"),
    "ARGUS_ST_013": RuleCapability("ARGUS_ST_013", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_014": RuleCapability("ARGUS_ST_014", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_015": RuleCapability("ARGUS_ST_015", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_016": RuleCapability("ARGUS_ST_016", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_017": RuleCapability("ARGUS_ST_017", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_018": RuleCapability("ARGUS_ST_018", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_019": RuleCapability("ARGUS_ST_019", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_020": RuleCapability("ARGUS_ST_020", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_021": RuleCapability("ARGUS_ST_021", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_022": RuleCapability("ARGUS_ST_022", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_023": RuleCapability("ARGUS_ST_023", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_024": RuleCapability("ARGUS_ST_024", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_025": RuleCapability("ARGUS_ST_025", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_026": RuleCapability("ARGUS_ST_026", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_027": RuleCapability("ARGUS_ST_027", frozenset(), PATTERN, "pattern"),
    "ARGUS_ST_028": RuleCapability("ARGUS_ST_028", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
    "ARGUS_ST_029": RuleCapability("ARGUS_ST_029", CONFIG_EXTENSIONS, STRUCTURED, "structured"),
}


def capability_for(rule_id: str) -> RuleCapability:
    return RULE_CAPABILITIES[rule_id]


__all__ = ["RULE_CAPABILITIES", "RuleCapability", "capability_for"]
