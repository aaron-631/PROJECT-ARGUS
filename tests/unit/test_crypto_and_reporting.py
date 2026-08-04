from pathlib import Path

import pytest

from src.reporting import JSONExporter, MarkdownExporter
from src.utils.crypto import Vault, VaultError, generate_vault_key, get_vault_key


def test_vault_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    key = b"k" * 32
    vault = Vault(tmp_path / ".vault", key=key)
    token = vault.encrypt("sensitive response")
    assert vault.decrypt(token) == b"sensitive response"
    with pytest.raises(VaultError):
        Vault(tmp_path / ".vault", key=b"z" * 32).decrypt(token)
    stored = vault.store("response", "sensitive response")
    assert vault.load("response") == b"sensitive response"
    assert stored.stat().st_mode & 0o077 == 0


def test_vault_key_generation_missing_key_and_rotation(tmp_path: Path) -> None:
    generated = generate_vault_key()
    assert len(generated) >= 43
    assert len(get_vault_key({"ARGUS_VAULT_KEY": generated})) == 32
    with pytest.raises(VaultError, match="missing vault key"):
        get_vault_key({})

    old_key = b"o" * 32
    new_key = b"n" * 32
    old = Vault(tmp_path / ".vault", key=old_key)
    old.store("rotating", "before rotation")
    rotated = Vault(
        tmp_path / ".vault",
        key=new_key,
        previous_keys={old.key_id or "old": old_key},
    )
    rotated.rotate("rotating", new_key)
    assert rotated.load("rotating") == b"before rotation"
    assert Vault(tmp_path / ".vault", key=new_key).load("rotating") == b"before rotation"


def test_report_exporters_are_stable_and_dual_format(tmp_path: Path) -> None:
    results = {
        "metadata": {
            "source_type": "local",
            "source": "fixture",
            "scan_id": "stable",
        },
        "configuration": {},
        "findings": [],
        "attack_results": [],
        "summary": {"max_risk": 0},
        "evaluation_methodology": "canonical_only",
    }
    json_path = JSONExporter().export(results, tmp_path / "report.json")
    MarkdownExporter().export(results, tmp_path / "report.md")
    first = json_path.read_text(encoding="utf-8")
    JSONExporter().export(results, tmp_path / "report-again.json")
    assert first == (tmp_path / "report-again.json").read_text(encoding="utf-8")
    assert "canonical_only" in (tmp_path / "report.md").read_text(encoding="utf-8")
