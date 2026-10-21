"""Shared PostgreSQL and Redis containers for integration tests (one pair per session)."""

import asyncio
import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import asyncpg
import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from redis.asyncio import Redis
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app.app_factory import create_app
from app.core.config import Audience
from app.core.mailer import MemoryMailer
from app.core.tasks import MemoryTaskQueue
from app.db_roles import RolePasswords, provision_roles
from tests.conftest import make_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]
DB_NAME = "vuln_veille"
ADMIN_PASSWORD = "admin-test-pw"
PASSWORDS = RolePasswords(
    migrator="migrator-test-password-0123456789",
    app="app-test-password-0123456789abcd",
    worker="worker-test-password-0123456789ab",
    portal="portal-test-password-0123456789ab",
)
ORIGINS = {"backoffice": "https://backoffice.test", "portal": "https://portal.test"}


@dataclass(frozen=True)
class Database:
    host: str
    port: int

    def dsn(self, user: str, password: str) -> str:
        return f"postgresql://{user}:{password}@{self.host}:{self.port}/{DB_NAME}"

    @property
    def admin_dsn(self) -> str:
        return self.dsn("admin", ADMIN_PASSWORD)


@pytest.fixture(scope="session")
def postgres() -> Iterator[PostgresContainer]:
    with PostgresContainer(
        "postgres:17-alpine", username="admin", password=ADMIN_PASSWORD, dbname=DB_NAME
    ) as container:
        yield container


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7-alpine") as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"


@pytest.fixture(scope="session")
async def database(postgres: PostgresContainer) -> Database:
    db = Database(postgres.get_container_host_ip(), int(postgres.get_exposed_port(5432)))
    admin = await asyncpg.connect(db.admin_dsn)
    try:
        await provision_roles(admin, DB_NAME, PASSWORDS)
        await provision_roles(admin, DB_NAME, PASSWORDS)  # idempotent
    finally:
        await admin.close()
    env = {**os.environ, "VV_DATABASE_URL_MIGRATOR": db.dsn("vv_migrator", PASSWORDS.migrator)}
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", "head", cwd=BACKEND_DIR, env=env
    )
    assert await process.wait() == 0
    return db


@pytest.fixture
async def clean_state(database: Database, redis_url: str) -> None:
    """Empties identity data, audit and rate-limit counters between tests."""
    admin = await asyncpg.connect(database.admin_dsn)
    try:
        await admin.execute(
            "TRUNCATE users, client_organizations, audit_events, connectors, cve_records, "
            "outbox_events, technologies, vulnerabilities, collected_items, watch_scopes, "
            "watch_sources, workflows, dedupe_keys, ai_models RESTART IDENTITY CASCADE"
        )
    finally:
        await admin.close()
    redis = Redis.from_url(redis_url)
    await redis.flushdb()
    await redis.aclose()


@dataclass
class Api:
    app: FastAPI
    client: httpx.AsyncClient
    mailer: MemoryMailer
    audience: Audience
    tasks: MemoryTaskQueue

    @property
    def prefix(self) -> str:
        return "/api/v1" if self.audience == "backoffice" else "/api/portal/v1"

    def url(self, path: str) -> str:
        return f"{self.prefix}{path}"


ApiFactory = Callable[[Audience], Awaitable[Api]]


@pytest.fixture
async def make_api(
    database: Database, redis_url: str, clean_state: None
) -> AsyncIterator[ApiFactory]:
    """Builds a running application and an HTTPS test client with the right Origin."""
    stack: list[tuple[FastAPI, httpx.AsyncClient]] = []

    async def factory(audience: Audience) -> Api:
        settings = make_settings(
            database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
            database_url_portal=SecretStr(database.dsn("vv_portal", PASSWORDS.portal)),
            redis_url=SecretStr(redis_url),
            backoffice_origin=ORIGINS["backoffice"],
            portal_origin=ORIGINS["portal"],
        )
        mailer = MemoryMailer()
        tasks = MemoryTaskQueue()
        app = create_app(audience, settings, mailer=mailer, tasks=tasks)
        context = app.router.lifespan_context(app)
        await context.__aenter__()
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=f"https://{audience}.test",
            headers={"origin": ORIGINS[audience]},
        )
        stack.append((app, client))
        app.state._lifespan = context
        return Api(app=app, client=client, mailer=mailer, audience=audience, tasks=tasks)

    yield factory
    for app, client in stack:
        await client.aclose()
        await app.state._lifespan.__aexit__(None, None, None)
