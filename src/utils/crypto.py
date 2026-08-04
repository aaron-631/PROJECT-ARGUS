"""AES-256-GCM vaulting with versioned envelopes and key rotation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultError(RuntimeError):
    """Raised when vault key material, lifecycle state, or ciphertext is invalid."""


_PREFIX = "argus-vault:v1:"
_NONCE_BYTES = 12


def _key_from_material(material: str | bytes) -> bytes:
    raw = material.encode() if isinstance(material, str) else material
    if len(raw) == 32:
        return raw
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(raw + b"=" * (-len(raw) % 4))
            if len(decoded) == 32:
                return decoded
        except (ValueError, binascii.Error):
            continue
    try:
        decoded = bytes.fromhex(raw.decode())
        if len(decoded) == 32:
            return decoded
    except (ValueError, UnicodeDecodeError):
        pass
    raise VaultError("vault key must be exactly 32 bytes or encoded AES-256 key material")


def generate_vault_key() -> str:
    """Generate printable, random AES-256 key material for ``ARGUS_VAULT_KEY``."""

    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")


def vault_key_id(key: bytes | str) -> str:
    """Return a non-secret stable identifier used to select rotated keys."""

    return hashlib.sha256(_key_from_material(key)).hexdigest()[:16]


def get_vault_key(
    environ: Mapping[str, str] | None = None, variable: str = "ARGUS_VAULT_KEY"
) -> bytes:
    env = environ if environ is not None else os.environ
    value = env.get(variable)
    if not value:
        raise VaultError(f"missing vault key environment variable: {variable}")
    return _key_from_material(value)


def get_vault_key_id(
    environ: Mapping[str, str] | None = None,
    key: bytes | str | None = None,
    variable: str = "ARGUS_VAULT_KEY_ID",
) -> str:
    env = environ if environ is not None else os.environ
    configured = env.get(variable)
    if configured and re.fullmatch(r"[A-Za-z0-9_.-]{4,64}", configured):
        return configured
    material = key if key is not None else get_vault_key(environ)
    return vault_key_id(material)


def _aad(version: int, key_id: str) -> bytes:
    return f"argus-vault:v{version}:{key_id}".encode("ascii")


def _encode_envelope(payload: bytes, material: bytes, key_id: str) -> str:
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(material).encrypt(nonce, payload, _aad(1, key_id))
    envelope = {
        "version": 1,
        "key_id": key_id,
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("="),
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    return _PREFIX + encoded


def _decode_envelope(token: str) -> dict[str, object] | None:
    if not token.startswith(_PREFIX):
        return None
    try:
        encoded = token[len(_PREFIX) :]
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise VaultError("invalid vault envelope") from exc
    if not isinstance(value, dict) or value.get("version") != 1:
        raise VaultError("unsupported vault envelope version")
    if not isinstance(value.get("key_id"), str):
        raise VaultError("vault envelope is missing a key identifier")
    if not isinstance(value.get("nonce"), str) or not isinstance(value.get("ciphertext"), str):
        raise VaultError("vault envelope is incomplete")
    return value


def encrypt_payload(
    payload: str | bytes,
    key: bytes | str | None = None,
    associated_data: bytes | None = None,
    key_id: str | None = None,
) -> str:
    """Encrypt data using AES-256-GCM and a fresh nonce for every call."""

    material = _key_from_material(key) if key is not None else get_vault_key()
    plaintext = payload.encode("utf-8") if isinstance(payload, str) else payload
    resolved_id = key_id or get_vault_key_id(key=material)
    if associated_data is not None:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(material).encrypt(nonce, plaintext, associated_data)
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return _encode_envelope(plaintext, material, resolved_id)


def decrypt_payload(
    token: str,
    key: bytes | str | None = None,
    associated_data: bytes | None = None,
) -> bytes:
    material = _key_from_material(key) if key is not None else get_vault_key()
    envelope = _decode_envelope(token)
    try:
        if envelope is not None:
            key_id = str(envelope["key_id"])
            nonce_b64 = str(envelope["nonce"])
            ciphertext_b64 = str(envelope["ciphertext"])
            nonce = base64.urlsafe_b64decode(nonce_b64 + "=" * (-len(nonce_b64) % 4))
            ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + "=" * (-len(ciphertext_b64) % 4))
            return AESGCM(material).decrypt(
                nonce,
                ciphertext,
                associated_data if associated_data is not None else _aad(1, key_id),
            )
        combined = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(combined) <= _NONCE_BYTES:
            raise ValueError("ciphertext is too short")
        return AESGCM(material).decrypt(
            combined[:_NONCE_BYTES], combined[_NONCE_BYTES:], associated_data
        )
    except (ValueError, binascii.Error, InvalidTag) as exc:
        raise VaultError("unable to decrypt vault payload") from exc


def _atomic_write(destination: Path, contents: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _vault_path(vault_dir: str | Path, name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise VaultError("vault filename contains unsafe characters")
    return Path(vault_dir) / f"{name}.vault"


def vault_payload(
    payload: str | bytes,
    vault_dir: str | Path,
    name: str,
    key: bytes | str | None = None,
    key_id: str | None = None,
) -> Path:
    destination = _vault_path(vault_dir, name)
    _atomic_write(destination, encrypt_payload(payload, key, key_id=key_id))
    return destination


def unvault_payload(path: str | Path, key: bytes | str | None = None) -> bytes:
    try:
        token = Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise VaultError("unable to read vault payload") from exc
    return decrypt_payload(token, key)


class Vault:
    def __init__(
        self,
        vault_dir: str | Path = ".vault",
        key: bytes | str | None = None,
        key_id: str | None = None,
        previous_keys: Mapping[str, bytes | str] | None = None,
    ) -> None:
        self.vault_dir = Path(vault_dir)
        self.key = key
        self.key_id = key_id or (vault_key_id(key) if key is not None else None)
        self.previous_keys = {
            identifier: _key_from_material(material)
            for identifier, material in (previous_keys or {}).items()
        }

    def _current_key(self) -> bytes:
        return _key_from_material(self.key) if self.key is not None else get_vault_key()

    def _current_key_id(self) -> str:
        return self.key_id or get_vault_key_id(key=self._current_key())

    def encrypt(self, payload: str | bytes) -> str:
        return encrypt_payload(payload, self._current_key(), key_id=self._current_key_id())

    def decrypt(self, token: str) -> bytes:
        envelope = _decode_envelope(token)
        if envelope is None:
            return decrypt_payload(token, self._current_key())
        key_id = str(envelope["key_id"])
        if (
            self.key_id is None
            or key_id == self.key_id
            or key_id == vault_key_id(self._current_key())
        ):
            return decrypt_payload(token, self._current_key())
        previous = self.previous_keys.get(key_id)
        if previous is None:
            raise VaultError(f"no vault key configured for key id: {key_id}")
        return decrypt_payload(token, previous)

    def store(self, name: str, payload: str | bytes) -> Path:
        return vault_payload(
            payload,
            self.vault_dir,
            name,
            self._current_key(),
            self._current_key_id(),
        )

    def load(self, name: str) -> bytes:
        path = _vault_path(self.vault_dir, name)
        try:
            token = path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise VaultError("unable to read vault payload") from exc
        return self.decrypt(token)

    def rotate(self, name: str, new_key: bytes | str, new_key_id: str | None = None) -> Path:
        """Decrypt one stored item with the configured key set and rewrite it atomically."""

        plaintext = self.load(name)
        destination = _vault_path(self.vault_dir, name)
        new_material = _key_from_material(new_key)
        return_path = destination
        _atomic_write(
            destination,
            encrypt_payload(
                plaintext, new_material, key_id=new_key_id or vault_key_id(new_material)
            ),
        )
        return return_path

    def rotate_all(self, new_key: bytes | str, new_key_id: str | None = None) -> list[Path]:
        """Rotate every vault item, returning paths in deterministic order."""

        paths = sorted(self.vault_dir.glob("*.vault"))
        return [self.rotate(path.stem, new_key, new_key_id) for path in paths]


__all__ = [
    "Vault",
    "VaultError",
    "decrypt_payload",
    "encrypt_payload",
    "generate_vault_key",
    "get_vault_key",
    "get_vault_key_id",
    "unvault_payload",
    "vault_key_id",
    "vault_payload",
]
