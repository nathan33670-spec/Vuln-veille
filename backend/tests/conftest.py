from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from app.app_factory import create_app
from app.core.config import Audience, Settings

PLACEHOLDER_DSN = SecretStr("postgresql://unused:unused@127.0.0.1:1/unused")


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "database_url_app": PLACEHOLDER_DSN,
        "database_url_portal": PLACEHOLDER_DSN,
        "database_url_worker": PLACEHOLDER_DSN,
        "database_url_migrator": PLACEHOLDER_DSN,
        "redis_url": SecretStr("redis://127.0.0.1:1/0"),
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
