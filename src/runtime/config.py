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
    for environment_name, config_key in {
        "ARGUS_RUNTIME_LISTEN_HOST": "listen_host",
        "ARGUS_RUNTIME_LISTEN_PORT": "listen_port",
        "ARGUS_RUNTIME_MAX_BODY_BYTES": "max_body_bytes",
        "ARGUS_RUNTIME_TIMEOUT_SECONDS": "request_timeout_seconds",
        "ARGUS_RUNTIME_ALLOW_BUFFERED_STREAMING": "allow_buffered_streaming",
        "ARGUS_RUNTIME_REQUIRE_CLIENT_AUTH": "require_client_auth",
        "ARGUS_RUNTIME_PROTECT_METRICS": "protect_metrics",
        "ARGUS_RUNTIME_APPROVAL_SERVICE_URL": "approval_service_url",
        "ARGUS_RUNTIME_AUDIT_SINK_URL": "audit_sink_url",
        "ARGUS_RUNTIME_APPROVAL_SERVICE_TIMEOUT_SECONDS": "approval_service_timeout_seconds",
        "ARGUS_RUNTIME_AUDIT_SINK_TIMEOUT_SECONDS": "audit_sink_timeout_seconds",
        "ARGUS_RUNTIME_AUDIT_SINK_MAX_RETRIES": "audit_sink_max_retries",
    }.items():
        if env.get(environment_name):
            merged[config_key] = env[environment_name]
    if env.get("ARGUS_RUNTIME_FORWARD_HEADERS"):
        merged["forward_headers"] = [
            header.strip()
            for header in env["ARGUS_RUNTIME_FORWARD_HEADERS"].split(",")
            if header.strip()
        ]
    if isinstance(merged.get("audit_path"), str):
        merged["audit_path"] = os.path.expandvars(merged["audit_path"])
    try:
        return RuntimeConfig.model_validate(merged)
    except Exception as exc:
        raise RuntimeConfigurationError(f"invalid runtime configuration: {exc}") from exc


__all__ = ["RuntimeConfigurationError", "load_runtime_config"]
