"""Vault keys: one X25519 key pair per purpose, identified by a short key id.

- A **public key** (``<id>:<base64>``) lets a component seal new secrets.
- A **keyring** lists private keys (``<id>:<base64>``, one per line, current first);
  older keys stay listed until ``vault-rotate`` has re-wrapped every secret.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KEY_BYTES = 32
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class SecretPurpose(StrEnum):
    LLM = "llm"
    SOURCE = "source"
    CONNECTOR = "connector"
    WEBHOOK = "webhook"


class KeyFormatError(ValueError):
    """A key or keyring is malformed. The message never contains key material."""


def _split(entry: str, what: str) -> tuple[str, bytes]:
    key_id, sep, encoded = entry.strip().partition(":")
    if not sep or not _KEY_ID.fullmatch(key_id):
        raise KeyFormatError(f"{what}: expected '<key id>:<base64>'")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyFormatError(f"{what} {key_id}: invalid base64") from exc
    if len(raw) != KEY_BYTES:
        raise KeyFormatError(f"{what} {key_id}: expected {KEY_BYTES} bytes")
    return key_id, raw


def public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class PublicKey:
    key_id: str
    key: X25519PublicKey

    @classmethod
    def parse(cls, entry: str) -> "PublicKey":
        key_id, raw = _split(entry, "public key")
        return cls(key_id, X25519PublicKey.from_public_bytes(raw))

    @property
    def raw(self) -> bytes:
        return public_bytes(self.key)

    def encode(self) -> str:
        return f"{self.key_id}:{base64.b64encode(self.raw).decode()}"


@dataclass(frozen=True)
class Keyring:
    keys: tuple[tuple[str, X25519PrivateKey], ...]

    @classmethod
    def parse(cls, text: str) -> "Keyring":
        entries = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
        if not entries:
            raise KeyFormatError("keyring is empty")
        keys: list[tuple[str, X25519PrivateKey]] = []
        for entry in entries:
            key_id, raw = _split(entry, "private key")
            if any(existing == key_id for existing, _ in keys):
                raise KeyFormatError(f"keyring: duplicate key id {key_id}")
            keys.append((key_id, X25519PrivateKey.from_private_bytes(raw)))
        return cls(tuple(keys))

    @property
    def current(self) -> PublicKey:
        key_id, private = self.keys[0]
        return PublicKey(key_id, private.public_key())

    def private(self, key_id: str) -> X25519PrivateKey | None:
        return next((key for kid, key in self.keys if kid == key_id), None)


def generate(key_id: str) -> tuple[str, str]:
    """Returns a new (keyring line, public key) pair for ``key_id``."""
    if not _KEY_ID.fullmatch(key_id):
        raise KeyFormatError("key id: lowercase letters, digits and dashes, 32 at most")
    private = X25519PrivateKey.generate()
    raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    line = f"{key_id}:{base64.b64encode(raw).decode()}"
    return line, PublicKey(key_id, private.public_key()).encode()
