import base64
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from app.app_factory import create_app
from app.core.config import Audience, Settings
from app.vault.keys import Keyring, SecretPurpose, generate

PLACEHOLDER_DSN = SecretStr("postgresql://unused:unused@127.0.0.1:1/unused")


# One vault key pair per purpose for the whole test session (never written to disk).
_VAULT_KEYS = {purpose: generate(f"test-{purpose}") for purpose in SecretPurpose}
TEST_KEYRINGS = {purpose: Keyring.parse(line) for purpose, (line, _) in _VAULT_KEYS.items()}


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "database_url_app": PLACEHOLDER_DSN,
        "database_url_portal": PLACEHOLDER_DSN,
        "database_url_worker": PLACEHOLDER_DSN,
        "database_url_migrator": PLACEHOLDER_DSN,
        "redis_url": SecretStr("redis://127.0.0.1:1/0"),
        "secret_key": SecretStr("test-secret-key-0123456789abcdef-0123456789"),
        "kek_totp": SecretStr(base64.b64encode(b"k" * 32).decode()),
        "password_hash_profile": "fast-insecure-tests-only",
        # The APIs only get public keys, like in production (ADR-013).
        **{f"vault_public_key_{p}": public for p, (_, public) in _VAULT_KEYS.items()},
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture(params=["backoffice", "portal"])
def audience(request: pytest.FixtureRequest) -> Audience:
    value: Audience = request.param
    return value


@pytest.fixture
def app(audience: Audience) -> FastAPI:
    return create_app(audience, make_settings())


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    # The lifespan is not started: unit tests never touch PostgreSQL or Redis.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
