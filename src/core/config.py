"""Configuration loading and profile resolution."""

from __future__ import annotations

import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from src.models.config import ArgusConfig


class ConfigurationError(ValueError):
    """Raised when a configuration file or profile is invalid."""


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ConfigurationError(f"unable to read configuration: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"malformed YAML configuration: {path}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"configuration must be a mapping: {path}")
    return value


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _default_config_path() -> Path:
    """Find repository or installed-package defaults without using cwd only."""

    relative = Path("config/default_config.yaml")
    candidates = (
        relative,
        Path(__file__).resolve().parents[2] / relative,
        Path(sys.prefix) / relative,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return relative


def load_config(
    profile: str = "default",
    config_path: str | Path | None = None,
    profiles_dir: str | Path | None = None,
    environ: dict[str, str] | None = None,
) -> ArgusConfig:
    """Load the default config and merge a named profile.

    Profile names are basenames by design.  This prevents a CLI profile value
    from escaping the repository's profile directory.
    """

    if not profile or Path(profile).name != profile or profile in {".", ".."}:
        raise ConfigurationError("profile must be a simple profile name")
    config_file = Path(config_path) if config_path else _default_config_path()
    profiles_root = Path(profiles_dir or config_file.parent / "profiles")
    merged = _read_yaml(config_file)
    profile_data: dict[str, Any] = {}
    if profile != "default":
        profile_file = profiles_root / f"{profile}.yaml"
        if not profile_file.is_file():
            raise ConfigurationError(f"profile not found: {profile}")
        profile_data = _read_yaml(profile_file)
    merged = _deep_merge(merged, profile_data)
    merged["profile"] = profile

    env = environ if environ is not None else os.environ
    if env.get("ARGUS_TARGET_ENDPOINT"):
        merged["target_endpoint"] = env["ARGUS_TARGET_ENDPOINT"]
    target_env_map = {
        "ARGUS_TARGET_PROVIDER": "provider",
        "ARGUS_TARGET_MODEL": "model",
        "ARGUS_TARGET_API_KEY_ENV": "api_key_env",
        "ARGUS_TARGET_AUTH_HEADER": "auth_header",
    }
    for environment_name, target_key in target_env_map.items():
        if env.get(environment_name):
            merged.setdefault("target", {})[target_key] = env[environment_name]
    if env.get("ARGUS_JUDGE_BACKEND"):
        merged.setdefault("judge", {})["backend"] = env["ARGUS_JUDGE_BACKEND"]
    if env.get("ARGUS_FAIL_ON"):
        merged.setdefault("reporting", {})["fail_on"] = env["ARGUS_FAIL_ON"].upper()

    try:
        return ArgusConfig.model_validate(merged)
    except Exception as exc:
        raise ConfigurationError(f"invalid Argus configuration: {exc}") from exc


__all__ = ["ConfigurationError", "load_config"]
