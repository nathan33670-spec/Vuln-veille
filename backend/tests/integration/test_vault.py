"""Secret vault: write-only API, team isolation, worker decryption, rotation."""

import uuid
from collections.abc import AsyncIterator

import asyncpg
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from app.vault.crypto import VaultError
from app.vault.keys import Keyring, SecretPurpose, generate
from app.vault.models import Secret
from app.vault.service import Vault, resolve_secret, rotate_purpose
from tests.conftest import TEST_KEYRINGS
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, SeededUser, create_user

pytestmark = pytest.mark.integration

VALUE = "ghp_integration-test-token-0123456789"
WORKER_VAULT = Vault(public_keys={}, keyrings=TEST_KEYRINGS)


async def _signed_in(api: Api, user: SeededUser) -> dict[str, str]:
    return {"x-csrf-token": await sign_in(api, user)}


async def _worker_session(
    database: Database, workspace_ids: tuple[uuid.UUID, ...] = (), *, admin: bool = False
) -> AsyncIterator[AsyncSession]:
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=workspace_ids, is_platform_admin=admin)
            yield db
    finally:
        await engine.dispose()


async def test_workspace_secret_is_write_only_and_usable_by_workers(
    make_api: ApiFactory, database: Database
) -> None:
    analyst = await create_user(
        database.admin_dsn, "ana@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    headers = await _signed_in(api, analyst)

    created = await api.client.post(
        api.url("/workspaces/cert/secrets"),
        json={"name": "github-token", "purpose": "source", "value": VALUE},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert VALUE not in created.text
    assert body["hint_last4"] == "6789"
    listed = await api.client.get(api.url("/workspaces/cert/secrets"))
    assert VALUE not in listed.text
    assert [s["name"] for s in listed.json()] == ["github-token"]

    conn = await asyncpg.connect(database.admin_dsn)
    try:
        row = await conn.fetchrow("SELECT ciphertext, dek_enc FROM secrets")
        audit = await conn.fetch(
            "SELECT details::text AS d FROM audit_events WHERE action LIKE 'secret.%'"
        )
    finally:
        await conn.close()
    assert row is not None
    assert VALUE.encode() not in bytes(row["ciphertext"]) + bytes(row["dek_enc"])
    assert audit
    assert all(VALUE not in r["d"] for r in audit)

    secret_id = uuid.UUID(body["id"])
    async for db in _worker_session(database, (WORKSPACE_IDS["cert"],)):
        plain = await resolve_secret(
            db,
            WORKER_VAULT,
            secret_id,
            purpose=SecretPurpose.SOURCE,
            workspace_id=WORKSPACE_IDS["cert"],
        )
        assert plain == VALUE
        with pytest.raises(VaultError):  # wrong purpose for this component
            await resolve_secret(
                db,
                WORKER_VAULT,
                secret_id,
                purpose=SecretPurpose.LLM,
                workspace_id=WORKSPACE_IDS["cert"],
            )
    async for db in _worker_session(database, (WORKSPACE_IDS["voc"],)):
        with pytest.raises(VaultError):  # a VOC task never reaches a CERT secret (RLS)
            await resolve_secret(
                db,
                WORKER_VAULT,
                secret_id,
                purpose=SecretPurpose.SOURCE,
                workspace_id=WORKSPACE_IDS["voc"],
            )

    replaced = await api.client.put(
        api.url(f"/workspaces/cert/secrets/{secret_id}/value"),
        json={"value": "short"},
        headers=headers,
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["hint_last4"] == ""
    assert replaced.json()["version"] == 2
    async for db in _worker_session(database, (WORKSPACE_IDS["cert"],)):
        assert (
            await resolve_secret(
                db,
                WORKER_VAULT,
                secret_id,
                purpose=SecretPurpose.SOURCE,
                workspace_id=WORKSPACE_IDS["cert"],
            )
            == "short"
        )

    deleted = await api.client.delete(
        api.url(f"/workspaces/cert/secrets/{secret_id}"), headers=headers
    )
    assert deleted.status_code == 204
    assert (await api.client.get(api.url("/workspaces/cert/secrets"))).json() == []


async def test_voc_administrators_never_see_cert_secrets(
    make_api: ApiFactory, database: Database
) -> None:
    cert = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    voc = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    cert_api = await make_api("backoffice")
    created = await cert_api.client.post(
        cert_api.url("/workspaces/cert/secrets"),
        json={"name": "stackexchange-key", "purpose": "source", "value": VALUE},
        headers=await _signed_in(cert_api, cert),
    )
    assert created.status_code == 201
    secret_id = created.json()["id"]

    voc_api = await make_api("backoffice")
    voc_headers = await _signed_in(voc_api, voc)
    assert (await voc_api.client.get(voc_api.url("/workspaces/cert/secrets"))).status_code == 404
    overwrite = await voc_api.client.put(
        voc_api.url(f"/workspaces/voc/secrets/{secret_id}/value"),
        json={"value": "attacker"},
        headers=voc_headers,
    )
    assert overwrite.status_code == 404
    # Even the global admin listing never includes workspace secrets.
    assert (await voc_api.client.get(voc_api.url("/admin/secrets"))).json() == []

    engine = create_engine(database.dsn("vv_app", PASSWORDS.app))
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, is_platform_admin=True, workspace_ids=(WORKSPACE_IDS["voc"],))
            visible = (await db.execute(select(Secret.id))).scalars().all()
    finally:
        await engine.dispose()
    assert visible == []


async def test_writes_need_step_up_and_valid_input(
    make_api: ApiFactory, database: Database
) -> None:
    admin = await create_user(
        database.admin_dsn, "admin@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    headers = await _signed_in(api, admin)

    bad_purpose = await api.client.post(
        api.url("/admin/secrets"),
        json={"name": "hook-key", "purpose": "webhook", "value": VALUE},
        headers=headers,
    )
    assert bad_purpose.status_code == 422
    assert bad_purpose.json()["detail"] == "purpose_not_allowed"
    too_long = await api.client.post(
        api.url("/admin/secrets"),
        json={"name": "nvd-api-key", "purpose": "source", "value": VALUE * 1000},
        headers=headers,
    )
    assert too_long.status_code == 422
    assert VALUE not in too_long.text  # validation errors never echo the value

    created = await api.client.post(
        api.url("/admin/secrets"),
        json={"name": "nvd-api-key", "purpose": "source", "value": VALUE},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    duplicate = await api.client.post(
        api.url("/admin/secrets"),
        json={"name": "nvd-api-key", "purpose": "source", "value": VALUE},
        headers=headers,
    )
    assert duplicate.status_code == 409

    conn = await asyncpg.connect(database.admin_dsn)
    try:
        await conn.execute("UPDATE sessions SET step_up_at = now() - interval '1 hour'")
    finally:
        await conn.close()
    stale = await api.client.put(
        api.url(f"/admin/secrets/{created.json()['id']}/value"),
        json={"value": "new"},
        headers=headers,
    )
    assert stale.status_code == 403
    assert stale.json()["detail"] == "step_up_required"


async def test_workers_cannot_create_secrets_and_rotation_rewraps(
    make_api: ApiFactory, database: Database
) -> None:
    admin = await create_user(
        database.admin_dsn, "admin@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    created = await api.client.post(
        api.url("/workspaces/voc/secrets"),
        json={"name": "bluesky-password", "purpose": "source", "value": VALUE},
        headers=await _signed_in(api, admin),
    )
    secret_id = uuid.UUID(created.json()["id"])

    worker = await asyncpg.connect(database.dsn("vv_worker", PASSWORDS.worker))
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await worker.execute("DELETE FROM secrets")
    finally:
        await worker.close()

    new_line, _ = generate("k-new")
    old = TEST_KEYRINGS[SecretPurpose.SOURCE]
    rotated_ring = Keyring((Keyring.parse(new_line).keys[0], *old.keys))
    vault = Vault(public_keys={}, keyrings={SecretPurpose.SOURCE: rotated_ring})
    async for db in _worker_session(database, admin=True):
        assert await rotate_purpose(db, vault, SecretPurpose.SOURCE) == 1
        assert await rotate_purpose(db, vault, SecretPurpose.SOURCE) == 0
    new_only = Vault(
        public_keys={}, keyrings={SecretPurpose.SOURCE: Keyring((rotated_ring.keys[0],))}
    )
    async for db in _worker_session(database, (WORKSPACE_IDS["voc"],)):
        assert (
            await resolve_secret(
                db,
                new_only,
                secret_id,
                purpose=SecretPurpose.SOURCE,
                workspace_id=WORKSPACE_IDS["voc"],
            )
            == VALUE
        )
