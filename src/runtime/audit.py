"""Sanitized, append-only, tamper-evident runtime audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.sanitization import sanitize_value


class AuditIntegrityError(RuntimeError):
    """Raised when an existing audit chain cannot be trusted."""


class AuditStorageError(RuntimeError):
    """Raised when an event cannot be durably appended."""


class AuditWriter:
    """Write one sanitized JSON object per line without storing prompts or responses."""

    def __init__(self, path: str | Path, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        self.hmac_key = hmac_key
        self._lock = threading.Lock()
        self._previous_hash = self._read_previous_hash()

    def _read_previous_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        if self.path.stat().st_size == 0:
            return "GENESIS"
        if not self.verify(self.path, self.hmac_key):
            raise AuditIntegrityError(f"existing audit chain failed verification: {self.path}")
        try:
            last_line = self.path.read_text(encoding="utf-8").splitlines()[-1]
            value = json.loads(last_line)
            event_hash = value.get("event_hash")
            if not isinstance(event_hash, str) or not event_hash:
                raise AuditIntegrityError(f"audit chain has no final event hash: {self.path}")
            if value.get("event_hmac") and self.hmac_key is None:
                raise AuditIntegrityError(
                    "audit chain is HMAC-protected but no audit key was configured"
                )
            return event_hash
        except (OSError, IndexError, UnicodeError, json.JSONDecodeError, AttributeError) as exc:
            raise AuditIntegrityError(f"unable to read audit chain: {self.path}") from exc

    def write(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            safe_event = sanitize_value(
                {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
            )
            canonical = json.dumps(safe_event, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(
                (self._previous_hash + canonical).encode("utf-8")
            ).hexdigest()
            record = {
                **safe_event,
                "previous_hash": self._previous_hash,
                "event_hash": event_hash,
            }
            if self.hmac_key:
                record["event_hmac"] = hmac.new(
                    self.hmac_key,
                    json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
            line = json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise AuditStorageError(f"unable to append audit event: {self.path}") from exc
            self._previous_hash = event_hash
        return record

    @staticmethod
    def verify(path: str | Path, hmac_key: bytes | None = None) -> bool:
        """Verify the hash chain and, when supplied, each event HMAC."""

        previous_hash = "GENESIS"
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return False
        for line in lines:
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    return False
                if record.get("previous_hash") != previous_hash:
                    return False
                event_hash = record.get("event_hash")
                if not isinstance(event_hash, str):
                    return False
                event = {
                    key: value
                    for key, value in record.items()
                    if key not in {"previous_hash", "event_hash", "event_hmac"}
                }
                canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
                expected_hash = hashlib.sha256(
                    (previous_hash + canonical).encode("utf-8")
                ).hexdigest()
                if not hmac.compare_digest(event_hash, expected_hash):
                    return False
                if hmac_key is not None:
                    supplied_hmac = record.get("event_hmac")
                    if not isinstance(supplied_hmac, str):
                        return False
                    signed = json.dumps(
                        {**event, "previous_hash": previous_hash, "event_hash": event_hash},
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    expected_hmac = hmac.new(hmac_key, signed, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(supplied_hmac, expected_hmac):
                        return False
                previous_hash = event_hash
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
        return True


__all__ = ["AuditIntegrityError", "AuditStorageError", "AuditWriter"]
