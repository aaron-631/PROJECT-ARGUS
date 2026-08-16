"""Pydantic v2 domain models for Argus.

Models deliberately reject unknown fields.  A security report is an audit
artifact, so silently accepting misspelled fields is more dangerous than
being slightly inconvenient for an extension author.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src import __version__


class ArgusModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class SourceMetadata(ArgusModel):
    source_type: Literal["local", "git"]
    source: str
    commit: str | None = None
    branch: str | None = None


class FileRecord(ArgusModel):
    path: str = Field(min_length=1)
    content: str = ""
    size_bytes: int = Field(default=0, ge=0)
    sha256: str = ""
    is_text: bool = True
    language: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("path")
    @classmethod
    def relative_path_only(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        parts = normalized.split("/")
        if (
            "\x00" in normalized
            or normalized.startswith("/")
            or any(part == ".." for part in parts)
        ):
            raise ValueError("file paths must be relative to the scan root")
        return normalized


class ScanContext(ArgusModel):
    source_path: str = Field(min_length=1)
    source_type: Literal["local", "git"]
    files: dict[str, FileRecord] = Field(default_factory=dict)
    source_metadata: SourceMetadata | None = None
    target_endpoint: str | None = None
    profile: str = "default"
    deployment_context: str = "custom"
    context_multiplier: float = Field(default=0.5, ge=0.1, le=1.0)
    # Parsed ASTs are an internal cache and are intentionally excluded from
    # JSON serialization; source file hashes remain the stable scan identity.
    documents: dict[str, Any] = Field(default_factory=dict, exclude=True)
    document_errors: list[str] = Field(default_factory=list)
    # Files intentionally not read (binary, non-UTF-8). Reported so a clean
    # scan can never be mistaken for full coverage.
    skipped_files: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def synchronize_file_keys(self) -> "ScanContext":
        for key, record in self.files.items():
            if key.replace("\\", "/") != record.path:
                raise ValueError("file mapping key must match FileRecord.path")
        return self

    def iter_files(self) -> list[FileRecord]:
        return [self.files[key] for key in sorted(self.files)]

    def get_content(self, path: str) -> str | None:
        record = self.files.get(path.replace("\\", "/"))
        return record.content if record else None


class Finding(ArgusModel):
    # Built-in rules use ARGUS_ST_NNN. Plugins must use their own prefix: the
    # ARGUS_ namespace is reserved so a third-party finding can never be
    # mistaken for a first-party one when a report is reviewed or audited.
    rule_id: str = Field(pattern=r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
    severity: Severity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    confidence_score: float = Field(ge=0.0, le=0.92)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_file: str | None = None
    line: int | None = Field(default=None, ge=1)
    deployment_context: str = "default"
    base_score: float = Field(default=1.0, ge=1.0, le=10.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    evaluation_methodology: str = "deterministic_static"
    remediation: str = ""
    # Standards metadata is additive and optional so third-party scanners can
    # continue emitting findings while gradually adopting the registry.
    owasp_ids: list[str] = Field(default_factory=list)
    atlas_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)

    @field_validator("rule_id")
    @classmethod
    def reserve_builtin_namespace(cls, value: str) -> str:
        """Keep ARGUS_ for built-ins so plugin findings stay distinguishable."""

        if value.startswith("ARGUS_") and not re.fullmatch(r"ARGUS_ST_[0-9]{3}", value):
            raise ValueError(
                "the ARGUS_ prefix is reserved for built-in rules; "
                "use your own prefix (for example ACME_ST_001)"
            )
        return value


class AttackProbe(ArgusModel):
    payload_id: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    category: str = "unspecified"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackResponse(ArgusModel):
    status_code: int = Field(default=200, ge=100, le=599)
    text: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    latency_ms: float | None = Field(default=None, ge=0.0)
    # Only normalized, bounded tool-call descriptors are retained. Arguments
    # are intentionally not copied into reports.
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class EvaluationResult(ArgusModel):
    canonical_result: dict[str, Any]
    heuristic_score: float = Field(ge=0.0, le=1.0)
    judge_score: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=10.0)
    evaluation_methodology: str


class JudgeDecision(ArgusModel):
    """The only semantic-judge result accepted by Argus."""

    model_config = ConfigDict(extra="forbid", strict=True)
    score: float = Field(ge=0.0, le=1.0)
    label: Literal["safe", "suspicious", "critical"]
    reason: str = Field(default="", max_length=2000)


class AttackResult(ArgusModel):
    module_id: str = Field(min_length=1)
    module_version: str = "1.0.0"
    attack_type: str = Field(min_length=1)
    payload_id: str = "unknown"
    payload: str = Field(min_length=1)
    raw_response: str = ""
    canonical_result: dict[str, Any] = Field(default_factory=dict)
    heuristic_score: float = Field(default=0.0, ge=0.0, le=1.0)
    judge_score: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    evaluation_methodology: str = "canonical_only"
    error: str | None = None
    owasp_ids: list[str] = Field(default_factory=list)
    atlas_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReportMetadata(ArgusModel):
    schema_version: str = "1.0"
    argus_version: str = __version__
    source_type: Literal["local", "git"]
    source: str
    profile: str = "default"
    dataset_version: str = "1.1.0"
    scan_id: str
    generated_at: str | None = None

    @model_validator(mode="after")
    def utc_timestamp_when_present(self) -> "ReportMetadata":
        if self.generated_at:
            # Validate the value but preserve the original representation in the report.
            datetime.fromisoformat(self.generated_at.replace("Z", "+00:00"))
        return self


class ScanReport(ArgusModel):
    metadata: ReportMetadata
    configuration: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    attack_results: list[AttackResult] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    evaluation_methodology: str = "canonical_only"

    @classmethod
    def with_timestamp(cls, **kwargs: Any) -> "ScanReport":
        metadata = kwargs.get("metadata")
        if isinstance(metadata, ReportMetadata) and metadata.generated_at is None:
            kwargs["metadata"] = metadata.model_copy(
                update={"generated_at": datetime.now(timezone.utc).isoformat()}
            )
        return cls(**kwargs)
