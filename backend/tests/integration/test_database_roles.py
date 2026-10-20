"""Least-privilege database roles, migrations and readiness against real services."""

import asyncio
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import asyncpg
import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import text
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app.app_factory import create_app
from app.core.db import create_engine
from app.db_roles import RolePasswords, provision_roles
from app.scheduler import run_tick
from tests.conftest import make_settings

pytestmark = pytest.mark.integration

BACKEND_DIR = Path(__file__).resolve().parents[2]
DB_NAME = "vuln_veille"
PASSWORDS = RolePasswords(
    migrator="migrator-test-password-0123456789",
    app="app-test-password-0123456789abcd",
    worker="worker-test-password-0123456789ab",
    portal="portal-test-password-0123456789ab",
)


@dataclass(frozen=True)
class Database:
    host: str
    port: int

    def dsn(self, user: str, password: str) -> str:
        return f"postgresql://{user}:{password}@{self.host}:{self.port}/{DB_NAME}"


@pytest.fixture(scope="module")
def postgres() -> Iterator[PostgresContainer]:
    with PostgresContainer(
        "postgres:17-alpine", username="admin", password="admin-test-pw", dbname=DB_NAME
    ) as container:
        yield container


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7-alpine") as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"


@pytest.fixture(scope="module")
async def database(postgres: PostgresContainer) -> Database:
    db = Database(postgres.get_container_host_ip(), int(postgres.get_exposed_port(5432)))
    admin = await asyncpg.connect(db.dsn("admin", "admin-test-pw"))
    try:
        await provision_roles(admin, DB_NAME, PASSWORDS)
        await provision_roles(admin, DB_NAME, PASSWORDS)  # idempotent
    finally:
        await admin.close()

    env = {
        **os.environ,
        "VV_DATABASE_URL_MIGRATOR": db.dsn("vv_migrator", PASSWORDS.migrator),
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", "head", cwd=BACKEND_DIR, env=env
    )
    assert await process.wait() == 0
    return db


async def _fails(dsn: str, statement: str) -> bool:
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(statement)
    except asyncpg.InsufficientPrivilegeError:
        return True
    finally:
        await conn.close()
    return False


async def test_roles_are_not_privileged(database: Database) -> None:
    conn = await asyncpg.connect(database.dsn("vv_migrator", PASSWORDS.migrator))
    try:
        rows = await conn.fetch(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
            "FROM pg_roles WHERE rolname LIKE 'vv\\_%'"
        )
    finally:
        await conn.close()
    assert {r["rolname"] for r in rows} == {"vv_migrator", "vv_app", "vv_worker", "vv_portal"}
    for row in rows:
        assert not row["rolsuper"]
        assert not row["rolbypassrls"]
        assert not row["rolcreaterole"]
        assert not row["rolcreatedb"]


async def test_baseline_migration_applied(database: Database) -> None:
    conn = await asyncpg.connect(database.dsn("vv_app", PASSWORDS.app))
    try:
        extensions = {r["extname"] for r in await conn.fetch("SELECT extname FROM pg_extension")}
        version = await conn.fetchval("SELECT version_num FROM alembic_version")
    finally:
        await conn.close()
    assert {"citext", "pg_trgm"} <= extensions
    assert version == "0002_iam"


async def test_runtime_roles_cannot_change_schema(database: Database) -> None:
    for role, password in (
        ("vv_app", PASSWORDS.app),
        ("vv_worker", PASSWORDS.worker),
        ("vv_portal", PASSWORDS.portal),
    ):
        assert await _fails(database.dsn(role, password), "CREATE TABLE intruder (id int)"), role


async def test_app_gets_dml_on_migrator_tables_but_portal_does_not(database: Database) -> None:
    migrator = await asyncpg.connect(database.dsn("vv_migrator", PASSWORDS.migrator))
    try:
        await migrator.execute("CREATE TABLE IF NOT EXISTS grant_probe (id int)")
    finally:
        await migrator.close()

    app = await asyncpg.connect(database.dsn("vv_app", PASSWORDS.app))
    try:
        await app.execute("INSERT INTO grant_probe VALUES (1)")
    finally:
        await app.close()
    assert await _fails(database.dsn("vv_portal", PASSWORDS.portal), "SELECT * FROM grant_probe")


async def test_readyz_with_real_services(database: Database, redis_url: str) -> None:
    settings = make_settings(
        database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
        database_url_portal=SecretStr(database.dsn("vv_portal", PASSWORDS.portal)),
        redis_url=SecretStr(redis_url),
    )
    for audience in ("backoffice", "portal"):
        app = create_app(audience, settings)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                response = await client.get("/readyz")
        assert response.status_code == 200, audience
        assert response.json() == {"status": "ready"}


async def test_readyz_reports_unavailable_without_leaking(database: Database) -> None:
    settings = make_settings(
        database_url_app=SecretStr(database.dsn("vv_app", "wrong-password")),
    )
    app = create_app("backoffice", settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


async def test_scheduler_tick_is_single_leader(database: Database) -> None:
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    calls: list[bool] = []

    async def nested_tick() -> None:
        # While this tick holds the lock, a concurrent tick must not run.
        calls.append(await run_tick(engine, _never_runs))

    try:
        ran = await run_tick(engine, nested_tick)
        async with engine.connect() as conn:
            held = (
                await conn.execute(text("SELECT count(*) FROM pg_locks WHERE locktype='advisory'"))
            ).scalar_one()
    finally:
        await engine.dispose()
    assert ran is True
    assert calls == [False]
    assert held == 0


async def _never_runs() -> None:
    raise AssertionError("a second scheduler ran concurrently")
