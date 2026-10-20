"""Vault operations: write-only management from the API, decryption in the workers.

The back-office only holds public keys (``Vault.seal``); ``Vault.reveal`` works only
where the purpose's keyring is mounted (ADR-013). Values are never logged, returned
by the API or put in audit details.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.ids import uuid7
from app.vault.crypto import Sealed, SecretBinding, VaultError, open_sealed, rewrap, seal
from app.vault.keys import KeyFormatError, Keyring, PublicKey, SecretPurpose
from app.vault.models import Secret

GLOBAL_PURPOSES = frozenset({SecretPurpose.LLM, SecretPurpose.SOURCE})
HINT_MIN_LENGTH = 16  # shorter values show no hint at all


class VaultConfigError(RuntimeError):
    """The vault keys are missing or inconsistent (startup or CLI error)."""


@dataclass(frozen=True)
class Vault:
    public_keys: Mapping[SecretPurpose, PublicKey]
    keyrings: Mapping[SecretPurpose, Keyring]

    @classmethod
    def from_settings(cls, settings: Settings) -> "Vault":
        public_keys: dict[SecretPurpose, PublicKey] = {}
        keyrings: dict[SecretPurpose, Keyring] = {}
        for purpose in SecretPurpose:
            try:
                configured = getattr(settings, f"vault_public_key_{purpose}")
                if configured:
                    public_keys[purpose] = PublicKey.parse(configured)
                path = (
                    settings.vault_keyring_dir and settings.vault_keyring_dir / f"{purpose}.keyring"
                )
                if path and path.is_file():
                    keyrings[purpose] = Keyring.parse(path.read_text())
            except KeyFormatError as exc:
                raise VaultConfigError(f"vault {purpose}: {exc}") from exc
            keyring = keyrings.get(purpose)
            if keyring is None:
                continue
            current = keyring.current
            if purpose not in public_keys:
                public_keys[purpose] = current
            elif public_keys[purpose].encode() != current.encode():
                raise VaultConfigError(
                    f"vault {purpose}: the public key does not match the keyring's current key"
                )
        return cls(public_keys, keyrings)

    def seal(
        self,
        purpose: SecretPurpose,
        secret_id: uuid.UUID,
        workspace_id: uuid.UUID | None,
        value: str,
    ) -> Sealed:
        recipient = self.public_keys.get(purpose)
        if recipient is None:
            raise HTTPException(status_code=503, detail="vault_not_configured")
        return seal(value, recipient, SecretBinding(purpose, secret_id, workspace_id))

    def reveal(self, secret: Secret) -> str:
        purpose = SecretPurpose(secret.purpose)
        keyring = self.keyrings.get(purpose)
        if keyring is None:
            raise VaultError(f"no {purpose} keyring in this component")
        return open_sealed(_sealed(secret), keyring, _binding(secret))

    def rewrap(self, secret: Secret) -> bool:
        purpose = SecretPurpose(secret.purpose)
        keyring = self.keyrings.get(purpose)
        if keyring is None:
            raise VaultError(f"no {purpose} keyring in this component")
        updated = rewrap(_sealed(secret), keyring, _binding(secret))
        if updated is None:
            return False
        secret.dek_enc, secret.kek_id = updated.dek_enc, updated.kek_id
        secret.rotated_at = datetime.now(UTC)
        return True


def _sealed(secret: Secret) -> Sealed:
    return Sealed(secret.ciphertext, secret.nonce, secret.dek_enc, secret.kek_id)


def _binding(secret: Secret) -> SecretBinding:
    return SecretBinding(SecretPurpose(secret.purpose), secret.id, secret.workspace_id)


def hint_for(value: str) -> str:
    return value[-4:] if len(value) >= HINT_MIN_LENGTH else ""


def _apply(secret: Secret, sealed: Sealed, value: str) -> None:
    secret.ciphertext, secret.nonce = sealed.ciphertext, sealed.nonce
    secret.dek_enc, secret.kek_id = sealed.dek_enc, sealed.kek_id
    secret.hint_last4 = hint_for(value)
    secret.value_updated_at = datetime.now(UTC)


async def create_secret(
    db: AsyncSession,
    vault: Vault,
    *,
    workspace_id: uuid.UUID | None,
    purpose: SecretPurpose,
    name: str,
    description: str,
    value: str,
    actor: uuid.UUID,
) -> Secret:
    if workspace_id is None and purpose not in GLOBAL_PURPOSES:
        raise HTTPException(status_code=422, detail="purpose_not_allowed")
    secret = Secret(
        id=uuid7(),
        workspace_id=workspace_id,
        purpose=purpose,
        name=name,
        description=description,
        created_by=actor,
        updated_by=actor,
        version=1,
    )
    _apply(secret, vault.seal(purpose, secret.id, workspace_id, value), value)
    db.add(secret)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="name_taken") from exc
    return secret


def replace_value(vault: Vault, secret: Secret, value: str, actor: uuid.UUID) -> None:
    purpose = SecretPurpose(secret.purpose)
    _apply(secret, vault.seal(purpose, secret.id, secret.workspace_id, value), value)
    secret.updated_by = actor
    secret.version += 1


async def get_secret(
    db: AsyncSession, secret_id: uuid.UUID, workspace_id: uuid.UUID | None
) -> Secret:
    """A secret of exactly this scope (RLS already hides the others: defence in depth)."""
    secret = await db.get(Secret, secret_id)
    if secret is None or secret.workspace_id != workspace_id:
        raise HTTPException(status_code=404, detail="not_found")
    return secret


async def list_secrets(db: AsyncSession, workspace_id: uuid.UUID | None) -> list[Secret]:
    query = select(Secret).order_by(Secret.name)
    query = (
        query.where(Secret.workspace_id.is_(None))
        if workspace_id is None
        else query.where(Secret.workspace_id == workspace_id)
    )
    return list((await db.execute(query)).scalars())


async def resolve_secret(
    db: AsyncSession,
    vault: Vault,
    secret_id: uuid.UUID,
    *,
    purpose: SecretPurpose,
    workspace_id: uuid.UUID | None,
) -> str:
    """Worker side: the plaintext of a secret usable by ``workspace_id``.

    A workspace may use its own secrets and the global ones; the purpose must match
    the component asking for it."""
    secret = await db.get(Secret, secret_id)
    if (
        secret is None
        or secret.purpose != purpose
        or secret.workspace_id not in (None, workspace_id)
    ):
        raise VaultError("secret not found for this scope")
    return vault.reveal(secret)


async def rotate_purpose(db: AsyncSession, vault: Vault, purpose: SecretPurpose) -> int:
    """Re-wraps every data key of ``purpose`` for the keyring's current key."""
    if purpose not in vault.keyrings:
        raise VaultConfigError(f"no {purpose} keyring available")
    current = vault.keyrings[purpose].current.key_id
    rows = await db.execute(
        select(Secret).where(Secret.purpose == purpose, Secret.kek_id != current)
    )
    count = 0
    for secret in rows.scalars():
        if vault.rewrap(secret):
            count += 1
    await db.commit()
    return count
