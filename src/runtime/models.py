"""Validated runtime-gateway data models."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator

from src.models.domain import ArgusModel

Decision = Literal["allow", "block", "review", "redact"]


class RuntimePolicyConfig(ArgusModel):
    """Deterministic policies for the campus-placement gateway."""

    block_prompt_patterns: list[str] = Field(
        default_factory=lambda: [
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            r"reveal\s+(?:the\s+)?(?:hidden\s+)?system\s+prompt",
            r"show\s+(?:me\s+)?the\s+developer\s+message",
            r"disable\s+(?:your\s+)?safety",
        ]
    )
    block_tools: list[str] = Field(
        default_factory=lambda: [
            "delete*",
            "drop*",
            "truncate*",
            "wipe*",
            "export_all_student_data",
        ]
    )
    approval_tools: list[str] = Field(
        default_factory=lambda: [
            "update_student_record",
            "send_external_email",
            "issue_offer",
        ]
    )
    allowed_email_domains: list[str] = Field(default_factory=lambda: ["university.edu"])
    block_output_patterns: list[str] = Field(
        default_factory=lambda: [
            r"-----BEGIN\s+[^-]+-----",
            r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{12,}\b",
            r"(?i)\b(?:api[_-]?key|password|secret)\s*[:=]\s*\S+",
        ]
    )
    redact_personal_data: bool = True


class RuntimeConfig(ArgusModel):
    """Operational settings for the runtime proxy."""

    upstream_url: str = Field(min_length=1)
    listen_host: str = "127.0.0.1"
    listen_port: int = Field(default=8080, ge=1, le=65535)
    max_body_bytes: int = Field(default=1_048_576, ge=1024, le=50_000_000)
    request_timeout_seconds: float = Field(default=30.0, gt=0.0, le=600.0)
    allow_buffered_streaming: bool = False
    forward_headers: list[str] = Field(
        default_factory=lambda: [
            "accept",
            "authorization",
            "content-type",
            "x-request-id",
            "x-api-key",
            "api-key",
            "anthropic-version",
            "anthropic-beta",
            "openai-organization",
            "openai-project",
        ]
    )
    approval_header: str = "X-Argus-Approval-Token"
    approval_token_env: str = "ARGUS_RUNTIME_APPROVAL_TOKEN"
    audit_path: str = "./runtime-audit/events.jsonl"
    audit_hmac_key_env: str = "ARGUS_RUNTIME_AUDIT_KEY"
    policy: RuntimePolicyConfig = Field(default_factory=RuntimePolicyConfig)

    @field_validator("upstream_url")
    @classmethod
    def http_upstream_only(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("upstream_url must be an absolute http or https URL")
        return value


class PolicyDecision(ArgusModel):
    """A reasoned runtime decision that is safe to audit and return."""

    decision: Decision
    reason_codes: list[str] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)
    redaction_count: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = ["Decision", "PolicyDecision", "RuntimeConfig", "RuntimePolicyConfig"]
