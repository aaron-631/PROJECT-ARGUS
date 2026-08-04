"""Deterministic runtime request and response policy enforcement."""

from __future__ import annotations

import fnmatch
import hmac
import json
import re
from collections.abc import Iterable
from typing import Any

from src.core.sanitization import sanitize

from .models import PolicyDecision, RuntimePolicyConfig

_EMAIL_RE = re.compile(r"\b[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)")


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _content_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        return " ".join(_strings(content))
    return ""


def _prompt_texts(body: dict[str, Any]) -> list[str]:
    messages = body.get("messages")
    if isinstance(messages, list):
        return [
            _content_text(message)
            for message in messages
            if isinstance(message, dict) and message.get("role") != "tool"
        ]
    for key in ("prompt", "input"):
        if isinstance(body.get(key), str):
            return [body[key]]
    return []


def _tool_name(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    function = value.get("function")
    if isinstance(function, dict) and isinstance(function.get("name"), str):
        return function["name"]
    for key in ("name", "tool_name", "tool"):
        if isinstance(value.get(key), str):
            return value[key]
    return None


def _tool_calls(body: dict[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    tool_keys = {"tool_call", "tool_calls", "tool_use", "tool_uses"}

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            if key in tool_keys:
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            calls.append(item)
                elif _tool_name(value):
                    calls.append(value)
                return
            if value.get("type") in tool_keys and _tool_name(value):
                calls.append(value)
                return
            for child_key, child in value.items():
                if child_key in tool_keys:
                    visit(child, child_key)
                elif isinstance(child, (dict, list)):
                    visit(child, child_key)
        elif isinstance(value, list):
            for child in value:
                visit(child, key)

    visit(body)
    return calls


def _tool_arguments(call: dict[str, Any]) -> Any:
    function = call.get("function")
    arguments = (
        function.get("arguments")
        if isinstance(function, dict)
        else call.get("arguments", call.get("input"))
    )
    if isinstance(arguments, str):
        try:
            return json.loads(arguments)
        except json.JSONDecodeError:
            return arguments
    return arguments


def _email_values(value: Any, key: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key.lower() in {"to", "recipient", "email", "email_address"}:
                yield from _strings(child)
            else:
                yield from _email_values(child, child_key)
    elif isinstance(value, list):
        for child in value:
            yield from _email_values(child, key)


def _redact_value(value: Any, redact_personal_data: bool) -> tuple[Any, int]:
    if isinstance(value, str):
        redacted = sanitize(value)
        if redact_personal_data:
            redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
            redacted = _PHONE_RE.sub("[REDACTED_PHONE]", redacted)
        return redacted, int(redacted != value)
    if isinstance(value, list):
        output_list: list[Any] = []
        count = 0
        for child in value:
            clean, child_count = _redact_value(child, redact_personal_data)
            output_list.append(clean)
            count += child_count
        return output_list, count
    if isinstance(value, dict):
        output_dict: dict[str, Any] = {}
        count = 0
        for key, child in value.items():
            if re.fullmatch(
                r"(?i)(authorization|api[_-]?key|access[_-]?token|password|secret)", str(key)
            ):
                output_dict[str(key)] = "[REDACTED]"
                count += int(child != "[REDACTED]")
                continue
            clean, child_count = _redact_value(child, redact_personal_data)
            output_dict[str(key)] = clean
            count += child_count
        return output_dict, count
    return value, 0


class RuntimePolicy:
    """Apply placement-agent policies without an LLM or external state."""

    def __init__(self, config: RuntimePolicyConfig) -> None:
        self.config = config
        self._prompt_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in config.block_prompt_patterns
        ]
        self._output_patterns = [re.compile(pattern) for pattern in config.block_output_patterns]

    def inspect_request(
        self, body: Any, approval_token: str | None, configured_token: str | None
    ) -> PolicyDecision:
        if not isinstance(body, dict):
            return PolicyDecision(decision="block", reason_codes=["INVALID_REQUEST_OBJECT"])

        prompt_text = " ".join(_prompt_texts(body))
        if any(pattern.search(prompt_text) for pattern in self._prompt_patterns):
            return PolicyDecision(decision="block", reason_codes=["PROMPT_INJECTION_BLOCKED"])

        return self._inspect_tools(body, approval_token, configured_token)

    def _inspect_tools(
        self, body: dict[str, Any], approval_token: str | None, configured_token: str | None
    ) -> PolicyDecision:
        calls = _tool_calls(body)
        names = sorted({name for call in calls if (name := _tool_name(call))})
        for name in names:
            if any(
                fnmatch.fnmatchcase(name.lower(), pattern.lower())
                for pattern in self.config.block_tools
            ):
                return PolicyDecision(
                    decision="block",
                    reason_codes=["DANGEROUS_TOOL_BLOCKED"],
                    tool_names=names,
                )

        approval_required = [
            name
            for name in names
            if any(
                fnmatch.fnmatchcase(name.lower(), pattern.lower())
                for pattern in self.config.approval_tools
            )
        ]
        if approval_required:
            approved = bool(
                configured_token
                and approval_token
                and hmac.compare_digest(approval_token, configured_token)
            )
            if not approved:
                return PolicyDecision(
                    decision="review",
                    reason_codes=["HUMAN_APPROVAL_REQUIRED"],
                    tool_names=names,
                    metadata={"approval_tools": approval_required},
                )

        allowed_domains = {
            domain.lower().lstrip("@").strip() for domain in self.config.allowed_email_domains
        }
        if allowed_domains:
            for call in calls:
                for candidate in _email_values(_tool_arguments(call)):
                    match = _EMAIL_RE.search(candidate)
                    if match and match.group(1).lower() not in allowed_domains:
                        return PolicyDecision(
                            decision="block",
                            reason_codes=["EXTERNAL_EMAIL_DOMAIN_BLOCKED"],
                            tool_names=names,
                        )

        return PolicyDecision(decision="allow", tool_names=names)

    def inspect_response(
        self,
        body: Any,
        approval_token: str | None = None,
        configured_token: str | None = None,
    ) -> tuple[PolicyDecision, Any]:
        if isinstance(body, dict):
            tool_decision = self._inspect_tools(body, approval_token, configured_token)
            if tool_decision.decision != "allow":
                return tool_decision, None
        raw_text = " ".join(_strings(body))
        if any(pattern.search(raw_text) for pattern in self._output_patterns):
            return PolicyDecision(decision="block", reason_codes=["SENSITIVE_OUTPUT_BLOCKED"]), None
        redacted, count = _redact_value(body, self.config.redact_personal_data)
        if count:
            return (
                PolicyDecision(
                    decision="redact",
                    reason_codes=["OUTPUT_REDACTED"],
                    redaction_count=count,
                ),
                redacted,
            )
        return PolicyDecision(decision="allow"), body


__all__ = ["RuntimePolicy"]
