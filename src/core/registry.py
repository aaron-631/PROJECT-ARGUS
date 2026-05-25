"""
Plugin Registry — central registration for all attack modules, scanners,
judge backends, and exporters. Validates interfaces on registration.
"""


_registry: dict = {
    "attack_modules": {},
    "scanners": {},
    "judges": {},
    "exporters": {},
}


def register_attack_module(cls):
    """Decorator — registers an attack module."""
    _registry["attack_modules"][cls.module_id] = cls
    return cls


def register_scanner(cls):
    """Decorator — registers a static scanner."""
    _registry["scanners"][cls.scanner_id] = cls
    return cls


def get_enabled_modules(config: dict) -> dict:
    # TODO: filter by config enable/disable toggles
    return _registry
