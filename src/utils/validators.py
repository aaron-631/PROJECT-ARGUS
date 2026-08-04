"""Small validation helpers shared by the CLI and tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def validate_score(value: Any, minimum: float = 0.0, maximum: float = 1.0) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("score must be numeric") from exc
    if not minimum <= score <= maximum:
        raise ValueError(f"score must be between {minimum} and {maximum}")
    return score


def validate_safe_relative_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or normalized == ".." or normalized.startswith("../"):
        raise ValueError("path must be relative")
    return normalized


def validate_json_schema(value: dict[str, Any], schema_path: str | Path) -> None:
    from jsonschema import ValidationError, validate

    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    try:
        validate(value, schema)
    except ValidationError as exc:
        raise ValueError(f"schema validation failed: {exc.message}") from exc


__all__ = ["validate_json_schema", "validate_safe_relative_path", "validate_score"]
