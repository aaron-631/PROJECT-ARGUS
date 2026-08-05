"""Deterministic plugin registry with interface and identity validation."""

from __future__ import annotations

from typing import Any

from src.interfaces.attack import BaseAttackModule
from src.interfaces.scanner import BaseStaticScanner

_registry: dict = {
    "attack_modules": {},
    "scanners": {},
    "judges": {},
    "exporters": {},
}


class RegistryError(ValueError):
    """Raised when a module violates the registry contract."""


def clear_registry() -> None:
    for group in _registry.values():
        group.clear()


def _register(group: str, cls: type[Any], interface: type[Any], identity: str) -> type[Any]:
    if not isinstance(cls, type) or not issubclass(cls, interface):
        raise RegistryError(f"{identity} must inherit {interface.__name__}")
    module_id = getattr(cls, identity, None)
    # A subclass must explicitly declare its release.  Inheriting the base
    # class placeholder does not satisfy the plugin contract.
    version = cls.__dict__.get("version")
    if not isinstance(module_id, str) or not module_id.strip():
        raise RegistryError(f"registered {group[:-1]} must declare {identity}")
    if not isinstance(version, str) or not version.strip():
        raise RegistryError(f"{module_id} must declare a module version")
    if module_id in _registry[group]:
        raise RegistryError(f"duplicate {group[:-1]} id: {module_id}")
    _registry[group][module_id] = cls
    return cls


def register_attack_module(cls):
    """Decorator — registers an attack module."""
    return _register("attack_modules", cls, BaseAttackModule, "module_id")


def register_scanner(cls):
    """Decorator — registers a static scanner."""
    return _register("scanners", cls, BaseStaticScanner, "scanner_id")


def register_judge(cls):
    from src.interfaces.judge import JudgeBackend

    return _register("judges", cls, JudgeBackend, "backend_id")


def register_exporter(cls):
    from src.interfaces.exporter import BaseExporter

    return _register("exporters", cls, BaseExporter, "exporter_id")


def get_registry() -> dict[str, dict[str, type[Any]]]:
    discover_builtin_modules()
    return {group: dict(sorted(items.items())) for group, items in _registry.items()}


def discover_builtin_modules() -> None:
    """Import builtins once, making discovery order stable."""

    from src.modules.attacks.data_extraction import DataExtractionModule
    from src.modules.attacks.jailbreak import JailbreakModule
    from src.modules.attacks.prompt_injection import PromptInjectionModule
    from src.modules.scanners.mcp_scanner import MCPScanner
    from src.interfaces.exporter import BaseExporter
    from src.interfaces.judge import (
        APIJudgeBackend,
        HTTPJudgeBackend,
        JudgeBackend,
        MockJudgeBackend,
        NullJudgeBackend,
    )
    from src.reporting.exporters import JSONExporter, MarkdownExporter, SARIFExporter

    builtins = [
        ("attack_modules", DataExtractionModule, BaseAttackModule, "module_id"),
        ("attack_modules", JailbreakModule, BaseAttackModule, "module_id"),
        ("attack_modules", PromptInjectionModule, BaseAttackModule, "module_id"),
        ("scanners", MCPScanner, BaseStaticScanner, "scanner_id"),
        ("judges", NullJudgeBackend, JudgeBackend, "backend_id"),
        ("judges", MockJudgeBackend, JudgeBackend, "backend_id"),
        ("judges", HTTPJudgeBackend, JudgeBackend, "backend_id"),
        ("judges", APIJudgeBackend, JudgeBackend, "backend_id"),
        ("exporters", JSONExporter, BaseExporter, "exporter_id"),
        ("exporters", MarkdownExporter, BaseExporter, "exporter_id"),
        ("exporters", SARIFExporter, BaseExporter, "exporter_id"),
    ]
    for group, cls, interface, identity in builtins:
        module_id = getattr(cls, identity)
        if module_id not in _registry[group]:
            _register(group, cls, interface, identity)

    try:
        from importlib.metadata import entry_points

        for group, interface, identity in (
            ("argus.scanners", BaseStaticScanner, "scanner_id"),
            ("argus.attacks", BaseAttackModule, "module_id"),
            ("argus.judges", JudgeBackend, "backend_id"),
            ("argus.exporters", BaseExporter, "exporter_id"),
        ):
            registry_group = {
                "argus.scanners": "scanners",
                "argus.attacks": "attack_modules",
                "argus.judges": "judges",
                "argus.exporters": "exporters",
            }[group]
            for ep in entry_points(group=group):
                try:
                    cls = ep.load()
                    module_id = getattr(cls, identity, None)
                    if module_id and module_id not in _registry[registry_group]:
                        _register(registry_group, cls, interface, identity)
                except Exception:
                    pass  # External plugin failed to load; continue
    except ImportError:
        pass


def get_enabled_modules(config: dict | Any) -> dict[str, dict[str, type[Any]]]:
    discover_builtin_modules()
    raw = config.as_dict() if hasattr(config, "as_dict") else config
    toggles = (
        raw.get("enabled_modules", {}) if isinstance(raw.get("enabled_modules", {}), dict) else {}
    )
    enabled = {
        "scanners": set(toggles.get("scanners", raw.get("scanners", _registry["scanners"]))),
        "attack_modules": set(
            toggles.get("attack_modules", raw.get("attacks", _registry["attack_modules"]))
        ),
    }
    disabled = raw.get("disabled_modules", [])
    disabled_set = set(disabled) if isinstance(disabled, list) else set()
    unknown_disabled = disabled_set - {
        module_id for items in _registry.values() for module_id in items
    }
    if unknown_disabled:
        raise RegistryError(f"unknown disabled module(s): {sorted(unknown_disabled)}")
    for group in ("scanners", "attack_modules"):
        unknown = enabled[group] - set(_registry[group])
        if unknown:
            raise RegistryError(f"unknown {group[:-1]} module(s): {sorted(unknown)}")
    result: dict[str, dict[str, type[Any]]] = {}
    for group, values in _registry.items():
        if group in enabled:
            result[group] = {
                key: value
                for key, value in sorted(values.items())
                if key in enabled[group] and key not in disabled_set
            }
        else:
            result[group] = dict(sorted(values.items()))
    return result


__all__ = [
    "RegistryError",
    "clear_registry",
    "discover_builtin_modules",
    "get_enabled_modules",
    "get_registry",
    "register_attack_module",
    "register_exporter",
    "register_judge",
    "register_scanner",
]
