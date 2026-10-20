"""Vault envelope encryption, keys and configuration (ADR-013)."""

import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.vault.admin import add_key
from app.vault.crypto import SecretBinding, VaultError, open_sealed, rewrap, seal
from app.vault.keys import KeyFormatError, Keyring, PublicKey, SecretPurpose, generate
from app.vault.models import Secret
from app.vault.service import Vault, VaultConfigError, hint_for
from tests.conftest import make_settings

WORKSPACE = uuid.UUID("01900000-0000-7000-8000-000000000001")


def _keyring(*key_ids: str) -> tuple[Keyring, list[str]]:
    pairs = [generate(k) for k in key_ids]
    return Keyring.parse("\n".join(line for line, _ in pairs)), [pub for _, pub in pairs]


def _binding(**changes: object) -> SecretBinding:
    values: dict[str, object] = {
        "purpose": SecretPurpose.SOURCE,
        "secret_id": uuid.UUID(int=1),
        "workspace_id": WORKSPACE,
    }
    values.update(changes)
    return SecretBinding(**values)  # type: ignore[arg-type]


def test_seal_and_open_round_trip() -> None:
    keyring, _ = _keyring("k1")
    sealed = seal("ghp_example-token-value", keyring.current, _binding())
    assert b"ghp_example" not in sealed.ciphertext + sealed.dek_enc
    assert sealed.kek_id == "k1"
    assert open_sealed(sealed, keyring, _binding()) == "ghp_example-token-value"


def test_each_secret_gets_its_own_data_key_and_nonce() -> None:
    keyring, _ = _keyring("k1")
    first = seal("same value", keyring.current, _binding())
    second = seal("same value", keyring.current, _binding())
    assert first.ciphertext != second.ciphertext
    assert first.dek_enc != second.dek_enc


@pytest.mark.parametrize(
    "changes",
    [
        {"secret_id": uuid.UUID(int=2)},
        {"workspace_id": uuid.UUID("01900000-0000-7000-8000-000000000002")},
        {"workspace_id": None},
        {"purpose": SecretPurpose.LLM},
    ],
)
def test_ciphertext_is_bound_to_its_row_workspace_and_purpose(changes: dict[str, object]) -> None:
    keyring, _ = _keyring("k1")
    sealed = seal("value", keyring.current, _binding())
    with pytest.raises(VaultError):
        open_sealed(sealed, keyring, _binding(**changes))


def test_tampering_is_detected() -> None:
    keyring, _ = _keyring("k1")
    sealed = seal("value", keyring.current, _binding())
    flipped = bytes([sealed.ciphertext[0] ^ 1]) + sealed.ciphertext[1:]
    with pytest.raises(VaultError):
        open_sealed(
            sealed.__class__(flipped, sealed.nonce, sealed.dek_enc, "k1"), keyring, _binding()
        )
    with pytest.raises(VaultError):
        open_sealed(
            sealed.__class__(sealed.ciphertext, sealed.nonce, sealed.dek_enc[:-1], "k1"),
            keyring,
            _binding(),
        )


def test_another_keyring_cannot_open() -> None:
    keyring, _ = _keyring("k1")
    other, _ = _keyring("k1")
    sealed = seal("value", keyring.current, _binding())
    with pytest.raises(VaultError):
        open_sealed(sealed, other, _binding())


def test_rotation_rewraps_for_the_current_key() -> None:
    old_line, _ = generate("k1")
    new_line, _ = generate("k2")
    old = Keyring.parse(old_line)
    sealed = seal("value", old.current, _binding())
    both = Keyring.parse(new_line + "\n" + old_line)
    rotated = rewrap(sealed, both, _binding())
    assert rotated is not None
    assert rotated.kek_id == "k2"
    assert rotated.ciphertext == sealed.ciphertext  # only the data key is re-wrapped
    assert rewrap(rotated, both, _binding()) is None
    new_only = Keyring.parse(new_line)
    assert open_sealed(rotated, new_only, _binding()) == "value"
    with pytest.raises(VaultError, match="k1"):
        open_sealed(sealed, new_only, _binding())


@pytest.mark.parametrize(
    "text",
    ["", "no-colon", "Bad_Id:AAAA", "k1:not base64!", "k1:" + "QUJD", "k1:{0}\nk1:{0}"],
)
def test_malformed_keyrings_are_refused_without_echoing_keys(text: str) -> None:
    text = text.format(generate("x")[0].split(":", 1)[1])
    with pytest.raises(KeyFormatError) as exc:
        Keyring.parse(text)
    payload = text.partition(":")[2]
    assert not payload or payload[:8] not in str(exc.value)


def test_api_vault_can_seal_but_never_reveal() -> None:
    vault = Vault.from_settings(make_settings())
    assert not vault.keyrings
    sealed = vault.seal(SecretPurpose.SOURCE, uuid.UUID(int=1), WORKSPACE, "value")
    secret = Secret(
        id=uuid.UUID(int=1),
        workspace_id=WORKSPACE,
        purpose="source",
        ciphertext=sealed.ciphertext,
        nonce=sealed.nonce,
        dek_enc=sealed.dek_enc,
        kek_id=sealed.kek_id,
    )
    with pytest.raises(VaultError, match="no source keyring"):
        vault.reveal(secret)


def test_unconfigured_purpose_refuses_to_seal() -> None:
    vault = Vault.from_settings(make_settings(vault_public_key_llm=None))
    with pytest.raises(HTTPException) as exc:
        vault.seal(SecretPurpose.LLM, uuid.UUID(int=1), None, "value")
    assert exc.value.detail == "vault_not_configured"


def test_keyring_files_are_loaded_and_checked_against_public_keys(tmp_path: Path) -> None:
    public = add_key(tmp_path, SecretPurpose.SOURCE, "k1")
    vault = Vault.from_settings(
        make_settings(vault_keyring_dir=tmp_path, vault_public_key_source=public)
    )
    assert SecretPurpose.SOURCE in vault.keyrings
    assert SecretPurpose.LLM not in vault.keyrings

    _, other_public = generate("k1")
    with pytest.raises(VaultConfigError, match="does not match"):
        Vault.from_settings(
            make_settings(vault_keyring_dir=tmp_path, vault_public_key_source=other_public)
        )


def test_add_key_prepends_and_refuses_duplicates(tmp_path: Path) -> None:
    add_key(tmp_path, SecretPurpose.LLM, "k1")
    public = add_key(tmp_path, SecretPurpose.LLM, "k2")
    keyring = Keyring.parse((tmp_path / "llm.keyring").read_text())
    assert [k for k, _ in keyring.keys] == ["k2", "k1"]
    assert keyring.current.encode() == PublicKey.parse(public).encode()
    with pytest.raises(VaultConfigError, match="duplicate"):
        add_key(tmp_path, SecretPurpose.LLM, "k1")


def test_hint_only_for_long_values() -> None:
    assert hint_for("short-value") == ""
    assert hint_for("a-sixteen-chars!") == "ars!"
