"""Structured document parser used by scanner capability routing."""

from __future__ import annotations

import ast
import json
import tomllib
from pathlib import Path
import yaml

from src.models import FileRecord, ScanContext
from src.models.documents import DocumentKind, ParsedDocument


def _line_map(content: str) -> dict[str, int]:
    mapping: dict[str, int] = {"": 1}
    for index, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        key = stripped.split(":", 1)[0].strip().strip("{}\"'")
        if key and key not in mapping:
            mapping[key] = index
    return mapping


def parse_file(record: FileRecord) -> ParsedDocument:
    suffix = Path(record.path).suffix.lower()
    line_map = _line_map(record.content)
    try:
        if suffix == ".json":
            return ParsedDocument(
                path=record.path,
                kind=DocumentKind.JSON,
                value=json.loads(record.content),
                line_map=line_map,
            )
        if suffix in {".yaml", ".yml"}:
            return ParsedDocument(
                path=record.path,
                kind=DocumentKind.YAML,
                value=yaml.safe_load(record.content),
                line_map=line_map,
            )
        if suffix == ".toml":
            return ParsedDocument(
                path=record.path,
                kind=DocumentKind.TOML,
                value=tomllib.loads(record.content),
                line_map=line_map,
            )
        if suffix == ".py":
            return ParsedDocument(
                path=record.path,
                kind=DocumentKind.PYTHON_AST,
                value=ast.parse(record.content, filename=record.path),
                line_map=line_map,
            )
        if record.is_text:
            return ParsedDocument(
                path=record.path,
                kind=DocumentKind.TEXT,
                value=record.content,
                line_map=line_map,
            )
        return ParsedDocument(path=record.path, kind=DocumentKind.OPAQUE, line_map=line_map)
    except (
        OSError,
        SyntaxError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
    ) as exc:
        kind = {
            ".json": DocumentKind.JSON,
            ".yaml": DocumentKind.YAML,
            ".yml": DocumentKind.YAML,
            ".toml": DocumentKind.TOML,
            ".py": DocumentKind.PYTHON_AST,
        }.get(suffix, DocumentKind.TEXT if record.is_text else DocumentKind.OPAQUE)
        return ParsedDocument(
            path=record.path,
            kind=kind,
            line_map=line_map,
            parse_error=f"{type(exc).__name__}: {str(exc)[:240]}",
        )


def parse_context(context: ScanContext) -> ScanContext:
    documents: dict[str, ParsedDocument] = {}
    errors: list[str] = []
    for record in context.iter_files():
        document = parse_file(record)
        documents[record.path] = document
        if document.parse_error:
            errors.append(f"{record.path}: {document.parse_error}")
    return context.model_copy(update={"documents": documents, "document_errors": errors})


__all__ = ["parse_context", "parse_file"]
