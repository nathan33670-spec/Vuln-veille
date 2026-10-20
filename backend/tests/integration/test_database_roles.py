"""Least-privilege database roles, migrations and readiness against real services."""

from pathlib import Path

import asyncpg
import httpx
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from pydantic import SecretStr
from sqlalchemy import text

from app.app_factory import create_app
from app.core.db import create_engine
from app.scheduler import run_tick
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Database

pytestmark = pytest.mark.integration

BACKEND = Path(__file__).resolve().parents[2]


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
    assert (
        version == ScriptDirectory.from_config(Config(BACKEND / "alembic.ini")).get_current_head()
    )


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
