"""Validated, hashed, versioned local attack dataset loading."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from src.models import AttackProbe


class DatasetError(ValueError):
    """Raised when a payload manifest or payload file is not trustworthy."""


_DATA_ROOT = Path(__file__).resolve().parents[3] / "data" / "attacks"
_MANIFEST = _DATA_ROOT / "manifest.json"


def _read_manifest() -> dict[str, Any]:
    try:
        value = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetError("attack dataset manifest is missing or malformed") from exc
    if not isinstance(value, dict) or not isinstance(value.get("version"), str):
        raise DatasetError("attack dataset manifest requires a version")
    datasets = value.get("datasets")
    if not isinstance(datasets, list) or not datasets:
        raise DatasetError("attack dataset manifest requires dataset entries")
    return value


def dataset_version() -> str:
    return str(_read_manifest()["version"])


def _manifest_entries(attack_type: str, expected_version: str | None) -> list[dict[str, str]]:
    manifest = _read_manifest()
    version = str(manifest["version"])
    if expected_version is not None and version != expected_version:
        raise DatasetError(
            f"attack dataset version mismatch: expected {expected_version}, found {version}"
        )
    entries: list[dict[str, str]] = []
    for raw_entry in manifest["datasets"]:
        if not isinstance(raw_entry, dict):
            raise DatasetError("attack dataset manifest contains a non-object entry")
        if not all(
            isinstance(raw_entry.get(key), str) for key in ("attack_type", "path", "sha256")
        ):
            raise DatasetError("attack dataset entries require attack_type, path, and sha256")
        if raw_entry["attack_type"] == attack_type:
            entries.append({key: str(raw_entry[key]) for key in ("attack_type", "path", "sha256")})
    if not entries:
        raise DatasetError(f"no dataset registered for attack type: {attack_type}")
    return entries


def _safe_path(relative_path: str) -> Path:
    path = (_DATA_ROOT / relative_path).resolve()
    try:
        path.relative_to(_DATA_ROOT.resolve())
    except ValueError as exc:
        raise DatasetError("attack dataset path escapes its root") from exc
    return path


def load_payloads(attack_type: str, expected_version: str | None = None) -> list[AttackProbe]:
    entries = _manifest_entries(attack_type, expected_version)
    manifest_version = dataset_version()
    probes: list[AttackProbe] = []
    seen_ids: set[str] = set()
    for entry in sorted(entries, key=lambda item: item["path"]):
        path = _safe_path(entry["path"])
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise DatasetError(f"unable to read attack dataset: {entry['path']}") from exc
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if digest != entry["sha256"]:
            raise DatasetError(f"attack dataset hash mismatch: {entry['path']}")
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DatasetError(f"malformed attack dataset: {entry['path']}") from exc
        if not isinstance(data, dict) or data.get("version") != manifest_version:
            raise DatasetError(f"attack dataset version mismatch in file: {entry['path']}")
        raw_items = data.get("payloads")
        if not isinstance(raw_items, list):
            raise DatasetError(f"attack dataset payloads must be a list: {entry['path']}")
        for index, item in enumerate(raw_items):
            if not isinstance(item, dict) or not isinstance(item.get("payload"), str):
                raise DatasetError(f"invalid payload at {entry['path']}:{index + 1}")
            payload_id = str(item.get("payload_id", f"{attack_type}-{index + 1:03d}"))
            if payload_id in seen_ids:
                raise DatasetError(f"duplicate payload id: {payload_id}")
            seen_ids.add(payload_id)
            metadata = item.get("metadata", {})
            if not isinstance(metadata, dict):
                raise DatasetError(f"payload metadata must be an object: {payload_id}")
            probes.append(
                AttackProbe(
                    payload_id=payload_id,
                    payload=item["payload"],
                    category=str(item.get("category", path.parent.name)),
                    metadata={"dataset_version": manifest_version, **metadata},
                )
            )
    return sorted(probes, key=lambda item: item.payload_id)


__all__ = ["DatasetError", "dataset_version", "load_payloads"]
