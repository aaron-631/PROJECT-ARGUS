"""Dataset manifest, version, and integrity checks."""

import pytest

from src.modules.attacks.dataset import DatasetError, dataset_version, load_payloads


def test_all_attack_datasets_are_versioned_and_hashed() -> None:
    assert dataset_version() == "1.0.0"
    assert len(load_payloads("prompt_injection", expected_version="1.0.0")) == 3
    assert len(load_payloads("jailbreaks", expected_version="1.0.0")) == 3
    assert len(load_payloads("data_extraction", expected_version="1.0.0")) == 3


def test_dataset_version_mismatch_fails_closed() -> None:
    with pytest.raises(DatasetError, match="version mismatch"):
        load_payloads("prompt_injection", expected_version="9.9.9")
