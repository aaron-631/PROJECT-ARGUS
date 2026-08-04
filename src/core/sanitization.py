"""Sanitize untrusted model output before it enters reports or judge prompts."""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (
        re.compile(  # noqa: E501
            r"(?i)(api[_-]?key|access[_-]?token|token|secret|password)\s*[:=]\s*['\"]?[^\s,'\"]+"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL), "[REDACTED_PEM]"),
    (re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{12,}\b"), "[REDACTED_KEY]"),
]
_SENSITIVE_KEYS = re.compile(
    r"(?i)(?:authorization|x-api-key|api[_-]?key|access[_-]?token|"
    r"token|secret|password|private[_-]?key)"
)


def _remove_invisible(value: str) -> str:
    cleaned: list[str] = []
    for char in value:
        category = unicodedata.category(char)
        # C0/C1 controls, format characters (zero-width and bidi controls),
        # and line separators are not useful in a model response destined for
        # a single-line audit field.
        if category.startswith("C") or category in {"Zl", "Zp"}:
            if char in {"\t", " ", "\n", "\r"}:
                cleaned.append(" ")
            continue
        cleaned.append(char)
    return re.sub(r"\s+", " ", "".join(cleaned)).strip()


def sanitize(raw_output: str) -> str:
    """Return a report-safe, single-line representation of untrusted text."""

    if not isinstance(raw_output, str):
        raw_output = str(raw_output)
    result = _remove_invisible(raw_output)
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize_for_judge(raw_output: str) -> str:
    """Sanitize and XML-escape text before putting it between judge delimiters."""

    result = sanitize(raw_output)
    # Escaping both tags and ampersands prevents a response from closing the
    # judge's target element or changing its surrounding prompt.
    return html.escape(result, quote=True)


def sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEYS.fullmatch(str(key)) else sanitize_value(item)
            for key, item in value.items()
        }
    return value


__all__ = ["sanitize", "sanitize_for_judge", "sanitize_value"]
