"""Periodic synchronisation of global connectors (NVD, CISA KEV, EPSS, CVE.org).

One generic Celery task (``collect.connector_sync``) runs the type's ``sync``: a
PostgreSQL advisory lock keeps one run at a time per connector, and the outcome is
recorded as the connector's health.
"""

import asyncio
import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.connectors.base import HealthResult, Sleep, SyncJob, get_type
from app.connectors.models import Connector
from app.connectors.runtime import build_context, record_health
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.rls import init_context
from app.net.safe_http import EgressError, SafeHttpClient
from app.vault.crypto import VaultError
from app.vault.service import Vault

SYNC_TASK = "collect.connector_sync"
log = get_logger(__name__)
Clock = Callable[[], datetime]


class SyncError(Exception):
    """A source answered unexpectedly; ``code`` is safe to store and show."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def lock_id(connector_id: uuid.UUID) -> int:
    digest = hashlib.sha256(f"connector_sync:{connector_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


async def run_sync(
    settings: Settings,
    connector_id: uuid.UUID,
    *,
    http: SafeHttpClient | None = None,
    sleep: Sleep = asyncio.sleep,
    clock: Clock = lambda: datetime.now(UTC),
) -> dict[str, int] | None:
    """Runs one synchronisation; None when skipped or failed. ``http``: tests only."""
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with engine.connect() as lock:
            got = await lock.execute(
                text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id(connector_id)}
            )
            if not got.scalar_one():
                log.info("sync_already_running", connector_id=str(connector_id))
                return None
            try:
                return await _run(settings, engine, connector_id, http, sleep, clock)
            finally:
                await lock.execute(
                    text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id(connector_id)}
                )
    finally:
        await engine.dispose()


async def _run(
    settings: Settings,
    engine: AsyncEngine,
    connector_id: uuid.UUID,
    http: SafeHttpClient | None,
    sleep: Sleep,
    clock: Clock,
) -> dict[str, int] | None:
    async with create_sessionmaker(engine)() as db:
        init_context(db)  # global connectors only: no workspace context
        connector = await db.get(Connector, connector_id)
        if connector is None or connector.workspace_id is not None or not connector.enabled:
            return None
        try:
            type_cls = get_type(connector.kind)
        except KeyError:
            return None
        if not type_cls.syncs:
            return None
        now = clock()
        kind = connector.kind
        try:
            type_, ctx = await build_context(db, settings, Vault.from_settings(settings), connector)
            if http is not None:
                ctx.http = http
            report = await type_.sync(SyncJob(db, ctx, connector_id, now, sleep))
        except (SyncError, EgressError) as exc:
            await _fail(db, connector_id, f"sync: {exc.code}", now)
            log.warning("sync_failed", kind=kind, code=exc.code)
            return None
        except VaultError:
            await _fail(db, connector_id, "secret_unavailable", now)
            return None
        connector = await db.get(Connector, connector_id)
        if connector is not None:
            record_health(connector, HealthResult(ok=True), now)
            await db.commit()
        log.info("sync_done", kind=kind, **report)
        return report


async def _fail(db: AsyncSession, connector_id: uuid.UUID, message: str, now: datetime) -> None:
    await db.rollback()
    connector = await db.get(Connector, connector_id)
    if connector is not None:
        record_health(connector, HealthResult(ok=False, message=message), now)
        await db.commit()
