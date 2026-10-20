"""Small cryptographic helpers.

- ``AesGcmBox``: AES-256-GCM with associated data, for secrets stored in the database.
- ``keyed_hash``: HMAC-SHA256 of high-entropy values (one-time tokens, recovery codes),
  so a database dump alone cannot be used to look them up.
"""

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_FORMAT_VERSION = b"\x01"
_NONCE_BYTES = 12


class DecryptionError(Exception):
    pass


class AesGcmBox:
    def __init__(self, key: bytes) -> None:
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        return _FORMAT_VERSION + nonce + self._aead.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, blob: bytes, associated_data: bytes) -> bytes:
        if len(blob) <= 1 + _NONCE_BYTES or blob[:1] != _FORMAT_VERSION:
            raise DecryptionError("unsupported ciphertext format")
        nonce = blob[1 : 1 + _NONCE_BYTES]
        try:
            return self._aead.decrypt(nonce, blob[1 + _NONCE_BYTES :], associated_data)
        except Exception as exc:  # InvalidTag: wrong key, tampered data or wrong context
            raise DecryptionError("cannot decrypt") from exc


def keyed_hash(key: bytes, value: str, purpose: str) -> str:
    """Domain-separated HMAC-SHA256, hex encoded."""
    return hmac.new(key, f"{purpose}\x00{value}".encode(), hashlib.sha256).hexdigest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
