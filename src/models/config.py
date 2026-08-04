"""Validated configuration models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class EngineConfig(ConfigModel):
    max_concurrent_attacks: int = Field(default=10, ge=1, le=1000)
    rate_limit_rps: float = Field(default=5.0, gt=0.0, le=10000.0)
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=600.0)
    max_retries: int = Field(default=3, ge=0, le=10)
    backoff_base_seconds: float = Field(default=0.25, ge=0.0, le=60.0)
    max_file_size_bytes: int = Field(default=1_048_576, ge=1024)


class JudgeConfig(ConfigModel):
    backend: str = "NullJudgeBackend"
    endpoint: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class ReportingConfig(ConfigModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])
    output_dir: str = "./reports"
    fail_on: str = "HIGH"

    @field_validator("formats")
    @classmethod
    def supported_formats(cls, value: list[str]) -> list[str]:
        normalized = [item.lower() for item in value]
        invalid = set(normalized) - {"json", "markdown"}
        if invalid:
            raise ValueError(f"unsupported report formats: {sorted(invalid)}")
        return normalized


class VaultConfig(ConfigModel):
    enabled: bool = True
    vault_dir: str = ".vault"


class ArgusConfig(ConfigModel):
    version: str = "1.0"
    profile: str = "default"
    description: str = ""
    deployment_context: Literal["production", "human_in_loop", "sandbox", "public", "custom"] = (
        "custom"
    )
    c_env: float = Field(default=0.5, ge=0.1, le=1.0)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    scanners: list[str] = Field(default_factory=lambda: ["mcp_scanner"])
    attacks: list[str] = Field(
        default_factory=lambda: ["prompt_injection", "jailbreak", "data_extraction"]
    )
    enabled_modules: dict[str, list[str]] = Field(default_factory=dict)
    disabled_modules: list[str] = Field(default_factory=list)
    target_endpoint: str | None = None
    dataset_version: str = "1.0.0"

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = ["ArgusConfig", "EngineConfig", "JudgeConfig", "ReportingConfig", "VaultConfig"]
