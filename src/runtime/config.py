"""Runtime gateway configuration loading with explicit environment overrides."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .models import RuntimeConfig


class RuntimeConfigurationError(ValueError):
    """Raised when runtime gateway configuration is invalid."""


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeConfigurationError(f"unable to read runtime configuration: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeConfigurationError("runtime configuration must be a mapping")
    return value


def load_runtime_config(
    path: str | Path = "config/runtime/placement_agent.yaml",
    environ: dict[str, str] | None = None,
) -> RuntimeConfig:
    """Load the runtime config and apply only deployment-safe overrides."""

    merged = _read_yaml(Path(path))
    env = environ if environ is not None else os.environ
    if env.get("ARGUS_RUNTIME_UPSTREAM_URL"):
        merged["upstream_url"] = env["ARGUS_RUNTIME_UPSTREAM_URL"]
    if env.get("ARGUS_RUNTIME_AUDIT_PATH"):
        merged["audit_path"] = env["ARGUS_RUNTIME_AUDIT_PATH"]
    try:
        return RuntimeConfig.model_validate(merged)
    except Exception as exc:
        raise RuntimeConfigurationError(f"invalid runtime configuration: {exc}") from exc


__all__ = ["RuntimeConfigurationError", "load_runtime_config"]
