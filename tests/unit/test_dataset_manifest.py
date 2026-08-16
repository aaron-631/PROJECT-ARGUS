"""Dataset manifest, version, and integrity checks."""

import json
from pathlib import Path

import pytest

from src.core.config import load_config
from src.modules.attacks.dataset import DatasetError, dataset_version, load_payloads


def test_all_attack_datasets_are_versioned_and_hashed() -> None:
    assert dataset_version() == "1.1.0"
    assert len(load_payloads("prompt_injection", expected_version="1.1.0")) == 12
    assert len(load_payloads("jailbreaks", expected_version="1.1.0")) == 6
    assert len(load_payloads("data_extraction", expected_version="1.1.0")) == 7
    indirect = load_payloads("indirect_prompt_injection", expected_version="1.1.0")
    assert len(indirect) == 3
    assert all(item.metadata["source_channel"] == "retrieved_context" for item in indirect)


def test_dataset_version_propagates_through_manifest_files_and_default_config() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / "data" / "attacks" / "manifest.json").read_text())
    assert manifest["version"] == "1.1.0"
    assert load_config().dataset_version == manifest["version"]
    for entry in manifest["datasets"]:
        payload_file = root / "data" / "attacks" / entry["path"]
        payloads = json.loads(payload_file.read_text())
        assert payloads["version"] == manifest["version"]


def test_dataset_version_mismatch_fails_closed() -> None:
    with pytest.raises(DatasetError, match="version mismatch"):
        load_payloads("prompt_injection", expected_version="9.9.9")
