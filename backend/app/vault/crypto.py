"""Envelope encryption of vault secrets (ADR-013, SECURITY.md §4.7).

Each secret has its own random data key (DEK). The secret is encrypted with the DEK
(AES-256-GCM); the DEK is wrapped for the purpose's public key: ephemeral X25519
exchange, HKDF-SHA256, AES-256-GCM. Sealing needs only the public key, so the API can
write secrets without being able to read any of them.

Associated data binds both layers to the purpose, the secret id, its workspace and the
key id: a ciphertext copied to another row, workspace or purpose fails to decrypt.
"""

import os
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.vault.keys import KEY_BYTES, Keyring, PublicKey, SecretPurpose, public_bytes

_NONCE = 12
_WRAP_VERSION = b"\x01"
_WRAPPED_LEN = 1 + KEY_BYTES + _NONCE + KEY_BYTES + 16


class VaultError(Exception):
    """Decryption failed or a key is missing. Never carries secret material."""


@dataclass(frozen=True)
class SecretBinding:
    """What a ciphertext is bound to (associated data)."""

    purpose: SecretPurpose
    secret_id: uuid.UUID
    workspace_id: uuid.UUID | None

    def aad(self, key_id: str) -> bytes:
        workspace = str(self.workspace_id) if self.workspace_id else "global"
        return f"vv-secret/v1|{self.purpose}|{self.secret_id}|{workspace}|{key_id}".encode()

    def data_aad(self) -> bytes:
        workspace = str(self.workspace_id) if self.workspace_id else "global"
        return f"vv-secret-data/v1|{self.purpose}|{self.secret_id}|{workspace}".encode()


@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes
    nonce: bytes
    dek_enc: bytes
    kek_id: str


def _wrap_key(shared: bytes, ephemeral: bytes, recipient: bytes, purpose: SecretPurpose) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=ephemeral + recipient,
        info=f"vv-dek-wrap/v1|{purpose}".encode(),
    ).derive(shared)


def wrap_dek(dek: bytes, recipient: PublicKey, binding: SecretBinding) -> bytes:
    ephemeral = X25519PrivateKey.generate()
    ephemeral_raw = public_bytes(ephemeral.public_key())
    key = _wrap_key(
        ephemeral.exchange(recipient.key), ephemeral_raw, recipient.raw, binding.purpose
    )
    nonce = os.urandom(_NONCE)
    wrapped = AESGCM(key).encrypt(nonce, dek, binding.aad(recipient.key_id))
    return _WRAP_VERSION + ephemeral_raw + nonce + wrapped


def unwrap_dek(dek_enc: bytes, kek_id: str, keyring: Keyring, binding: SecretBinding) -> bytes:
    private = keyring.private(kek_id)
    if private is None:
        raise VaultError(f"key {kek_id} is not in the {binding.purpose} keyring")
    if len(dek_enc) != _WRAPPED_LEN or dek_enc[:1] != _WRAP_VERSION:
        raise VaultError("unsupported wrapped key format")
    ephemeral_raw = dek_enc[1 : 1 + KEY_BYTES]
    nonce = dek_enc[1 + KEY_BYTES : 1 + KEY_BYTES + _NONCE]
    wrapped = dek_enc[1 + KEY_BYTES + _NONCE :]
    recipient = public_bytes(private.public_key())
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw))
        key = _wrap_key(shared, ephemeral_raw, recipient, binding.purpose)
        return AESGCM(key).decrypt(nonce, wrapped, binding.aad(kek_id))
    except (InvalidTag, ValueError) as exc:
        raise VaultError("secret key cannot be unwrapped") from exc


def seal(plaintext: str, recipient: PublicKey, binding: SecretBinding) -> Sealed:
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(_NONCE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode(), binding.data_aad())
    return Sealed(ciphertext, nonce, wrap_dek(dek, recipient, binding), recipient.key_id)


def open_sealed(sealed: Sealed, keyring: Keyring, binding: SecretBinding) -> str:
    dek = unwrap_dek(sealed.dek_enc, sealed.kek_id, keyring, binding)
    try:
        return AESGCM(dek).decrypt(sealed.nonce, sealed.ciphertext, binding.data_aad()).decode()
    except InvalidTag as exc:
        raise VaultError("secret cannot be decrypted") from exc


def rewrap(sealed: Sealed, keyring: Keyring, binding: SecretBinding) -> Sealed | None:
    """Re-wraps the data key for the keyring's current key; None if already current."""
    current = keyring.current
    if sealed.kek_id == current.key_id:
        return None
    dek = unwrap_dek(sealed.dek_enc, sealed.kek_id, keyring, binding)
    return Sealed(sealed.ciphertext, sealed.nonce, wrap_dek(dek, current, binding), current.key_id)
