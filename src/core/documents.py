"""Structured document parser used by scanner capability routing."""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
import yaml

from src.models import FileRecord, ScanContext
from src.models.documents import DocumentKind, ParsedDocument


def _strip_json5_comments(content: str) -> str:
    """Remove JavaScript comments without changing quoted string contents."""

    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(content):
        char = content[index]
        next_char = content[index + 1] if index + 1 < len(content) else ""
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
        elif char == "/" and next_char == "/":
            index += 2
            while index < len(content) and content[index] not in "\r\n":
                index += 1
        elif char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(content) and content[index : index + 2] != "*/":
                if content[index] in "\r\n":
                    output.append(content[index])
                index += 1
            index += 2
        else:
            output.append(char)
            index += 1
    return "".join(output)


def _load_json5_fallback(content: str) -> object:
    """Parse the JSON5 subset used by common agent config files.

    The optional ``json5`` dependency is the primary parser.  This fallback
    keeps a source checkout usable before dependencies are installed and
    handles comments, unquoted keys, single-quoted strings, and trailing
    commas through PyYAML's safe loader.
    """

    cleaned = _strip_json5_comments(content)
    cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
    try:
        return yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise json.JSONDecodeError("invalid JSON5 document", content, 0) from exc


def _load_json_document(content: str) -> object:
    try:
        return json.loads(content)
    except json.JSONDecodeError as original:
        try:
            import json5

            return json5.loads(content)
        except ImportError:
            try:
                return _load_json5_fallback(content)
            except json.JSONDecodeError:
                raise original
        except Exception:
            raise original


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
        if suffix in {".json", ".json5"}:
            return ParsedDocument(
                path=record.path,
                kind=DocumentKind.JSON,
                value=_load_json_document(record.content),
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
            ".json5": DocumentKind.JSON,
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
