from pathlib import Path

from src.core.registry import get_registry
from src.core.taxonomy import ATTACK_TAXONOMY, RULE_TAXONOMY
from src.modules.scanners.mcp_scanner import _RULES
from src.modules.scanners.rules import RULE_CAPABILITIES


def test_every_builtin_static_rule_has_a_reviewed_taxonomy_entry() -> None:
    assert set(_RULES) == set(RULE_CAPABILITIES) == set(RULE_TAXONOMY)
    for entry in RULE_TAXONOMY.values():
        assert entry.identifier
        assert entry.status in {"implemented", "partial", "not_covered"}
        assert all(Path(path).is_file() for path in entry.evidence)


def test_every_builtin_attack_module_has_a_reviewed_taxonomy_entry() -> None:
    attack_ids = set(get_registry()["attack_modules"])
    assert attack_ids == set(ATTACK_TAXONOMY)
    for entry in ATTACK_TAXONOMY.values():
        assert entry.identifier
        assert entry.status in {"implemented", "partial", "not_covered"}
        assert all(Path(path).is_file() for path in entry.evidence)
