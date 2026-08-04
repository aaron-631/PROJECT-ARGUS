"""Sanitized, append-only, tamper-evident runtime audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.sanitization import sanitize_value


class AuditWriter:
    """Write one sanitized JSON object per line without storing prompts or responses."""

    def __init__(self, path: str | Path, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        self.hmac_key = hmac_key
        self._lock = threading.Lock()
        self._previous_hash = self._read_previous_hash()

    def _read_previous_hash(self) -> str:
        try:
            last_line = self.path.read_text(encoding="utf-8").splitlines()[-1]
            value = json.loads(last_line)
            return str(value.get("event_hash", "GENESIS"))
        except (OSError, IndexError, json.JSONDecodeError):
            return "GENESIS"

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
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
            self._previous_hash = event_hash
        return record

    @staticmethod
    def verify(path: str | Path, hmac_key: bytes | None = None) -> bool:
        """Verify the hash chain and, when supplied, each event HMAC."""

        previous_hash = "GENESIS"
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
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


__all__ = ["AuditWriter"]
