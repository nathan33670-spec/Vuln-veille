"""Vault key administration (``python -m app.cli vault-keygen | vault-rotate``).

Rotation, without downtime:
1. ``vault-keygen`` adds a new key at the top of the keyring file and prints the new
   public key, to set as ``VV_VAULT_PUBLIC_KEY_<PURPOSE>`` for the back-office;
2. restart the components: new secrets are sealed for the new key, old ones still open;
3. ``vault-rotate`` re-wraps every data key for the new key;
4. remove the old line from the keyring, keep an offline backup, restart.
"""

import os
from pathlib import Path

from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from app.vault.keys import KeyFormatError, Keyring, SecretPurpose, generate
from app.vault.service import Vault, VaultConfigError, rotate_purpose


def add_key(keyring_dir: Path, purpose: SecretPurpose, key_id: str) -> str:
    """Prepends a new private key to ``<purpose>.keyring``; returns the public key."""
    path = keyring_dir / f"{purpose}.keyring"
    existing = path.read_text() if path.is_file() else ""
    line, public = generate(key_id)
    content = line + "\n" + existing
    try:
        Keyring.parse(content)  # refuses duplicates and malformed files before writing
    except KeyFormatError as exc:
        raise VaultConfigError(f"{path.name}: {exc}") from exc
    temporary = path.with_suffix(".keyring.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(content)
    temporary.replace(path)
    return public


async def rotate(settings: Settings, purpose: SecretPurpose) -> int:
    vault = Vault.from_settings(settings)
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with create_sessionmaker(engine)() as db:
            # Rotation covers every scope, global and all workspaces.
            init_context(db)
            await set_context(db, is_platform_admin=True)
            return await rotate_purpose(db, vault, purpose)
    finally:
        await engine.dispose()
