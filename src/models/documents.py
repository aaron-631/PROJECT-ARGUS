"""Validated representations of parsed source documents."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from .domain import ArgusModel


class DocumentKind(str, Enum):
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    PYTHON_AST = "python_ast"
    TEXT = "text"
    OPAQUE = "opaque"


class ParsedDocument(ArgusModel):
    path: str = Field(min_length=1)
    kind: DocumentKind
    value: Any = None
    line_map: dict[str, int] = Field(default_factory=dict)
    parse_error: str | None = None

    def line_for(self, key: str = "") -> int | None:
        return self.line_map.get(key) or self.line_map.get("") or 1


__all__ = ["DocumentKind", "ParsedDocument"]
