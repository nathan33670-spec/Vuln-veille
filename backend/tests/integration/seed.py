"""Direct database seeding for integration tests (administrator connection)."""

import base64
import json
import uuid
from dataclasses import dataclass

import asyncpg
import pyotp

from app.core.crypto import AesGcmBox
from app.core.ids import uuid7
from app.iam.passwords import hash_password

TEST_KEK = b"k" * 32  # matches tests.conftest.make_settings
DEFAULT_PASSWORD = "correct horse battery staple"
WORKSPACE_IDS = {
    "voc": uuid.UUID("01900000-0000-7000-8000-000000000001"),
    "cert": uuid.UUID("01900000-0000-7000-8000-000000000002"),
}


@dataclass(frozen=True)
class SeededUser:
    id: uuid.UUID
    email: str
    password: str
    totp_secret: str | None

    def totp_now(self) -> str:
        assert self.totp_secret is not None
        return pyotp.TOTP(self.totp_secret).now()


async def create_org(dsn: str, name: str, settings: dict[str, object] | None = None) -> uuid.UUID:
    conn = await asyncpg.connect(dsn)
    try:
        org_id = uuid7()
        await conn.execute(
            "INSERT INTO client_organizations (id, name, settings) VALUES ($1, $2, $3::jsonb)",
            org_id,
            name,
            json.dumps(settings or {}),
        )
        return org_id
    finally:
        await conn.close()


async def create_user(
    dsn: str,
    email: str,
    *,
    user_type: str = "internal",
    status: str = "active",
    password: str = DEFAULT_PASSWORD,
    workspaces: dict[str, str] | None = None,
    global_roles: tuple[str, ...] = (),
    client_org: uuid.UUID | None = None,
    client_role: str = "client_user",
    with_totp: bool = False,
) -> SeededUser:
    conn = await asyncpg.connect(dsn)
    try:
        user_id = uuid7()
        await conn.execute(
            "INSERT INTO users (id, email, display_name, user_type, status, password_hash) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            user_id,
            email,
            email.split("@", maxsplit=1)[0],
            user_type,
            status,
            hash_password(password, "fast-insecure-tests-only") if status != "invited" else None,
        )
        for role in global_roles:
            await conn.execute(
                "INSERT INTO user_global_roles (user_id, role) VALUES ($1, $2)", user_id, role
            )
        for slug, role in (workspaces or {}).items():
            await conn.execute(
                "INSERT INTO workspace_memberships (user_id, workspace_id, role) "
                "VALUES ($1, $2, $3)",
                user_id,
                WORKSPACE_IDS[slug],
                role,
            )
        if client_org is not None:
            await conn.execute(
                "INSERT INTO client_memberships (user_id, client_org_id, role) VALUES ($1, $2, $3)",
                user_id,
                client_org,
                client_role,
            )
        secret = None
        if with_totp:
            secret = pyotp.random_base32(32)
            await conn.execute(
                "INSERT INTO user_mfa_totp (user_id, secret_enc, confirmed_at) "
                "VALUES ($1, $2, now())",
                user_id,
                AesGcmBox(TEST_KEK).encrypt(secret.encode(), user_id.bytes),
            )
        return SeededUser(id=user_id, email=email, password=password, totp_secret=secret)
    finally:
        await conn.close()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
