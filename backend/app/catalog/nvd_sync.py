"""NVD synchronisation (spec 07 §3.1), run by the ``collect`` worker.

- Initial catch-up over ``backfill_days``, in windows of at most 120 days, with no
  events (it would launch hundreds of investigations at once).
- Then incremental windows from the end of the last successful one, minus a small
  overlap, to now. The cursor moves after each completed window: a failure resumes
  where it stopped and no window is lost; replays detect nothing new.
- Each page is committed with its change history and outbox events.
- One sync at a time per connector (PostgreSQL advisory lock).
"""

import asyncio
import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.nvd_parse import NvdParseError, parse_cve
from app.catalog.store import upsert_cve
from app.connectors.base import HealthResult
from app.connectors.models import Connector, ConnectorCursor
from app.connectors.runtime import build_context, record_health
from app.connectors.types.nvd import NvdClient, NvdConfig, NvdConnector, NvdError, Sleep
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.rls import init_context
from app.net.safe_http import EgressError, SafeHttpClient
from app.vault.service import Vault

STREAM = "cves"
log = get_logger(__name__)
Clock = Callable[[], datetime]


@dataclass
class SyncReport:
    windows: int = 0
    records: int = 0
    malformed: int = 0
    published: int = 0
    updated: int = 0
    backfill_records: int = 0


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse(value: Any) -> datetime | None:
    return datetime.fromisoformat(value) if isinstance(value, str) else None


async def _cursor(db: AsyncSession, connector_id: uuid.UUID, now: datetime) -> ConnectorCursor:
    cursor = await db.get(ConnectorCursor, (connector_id, STREAM))
    if cursor is None:
        cursor = ConnectorCursor(
            connector_id=connector_id, stream=STREAM, position={}, updated_at=now
        )
        db.add(cursor)
    return cursor


def _save(cursor: ConnectorCursor, now: datetime, **changes: Any) -> None:
    cursor.position = {**cursor.position, **changes}  # new dict: JSONB change is tracked
    cursor.updated_at = now


async def _window(
    db: AsyncSession,
    client: NvdClient,
    config: NvdConfig,
    start: datetime,
    end: datetime,
    *,
    backfill: bool,
    report: SyncReport,
    now: datetime,
) -> None:
    announce_within = timedelta(days=config.announce_published_within_days)
    async for page in client.window(start, end):
        for item in page:
            try:
                data = parse_cve(item)
            except NvdParseError:
                report.malformed += 1
                continue
            detected = await upsert_cve(
                db,
                data,
                source="nvd",
                now=now,
                backfill=backfill,
                announce_within=announce_within,
            )
            report.records += 1
            if backfill:
                report.backfill_records += 1
            elif detected.change_types == ["published"]:
                report.published += 1
            elif detected.change_types:
                report.updated += 1
        await db.commit()
    report.windows += 1


async def sync_nvd(
    db: AsyncSession, client: NvdClient, connector: Connector, config: NvdConfig, now: datetime
) -> SyncReport:
    report = SyncReport()
    window = timedelta(days=config.window_days)
    cursor = await _cursor(db, connector.id, now)
    position = cursor.position

    if not position.get("backfill_done"):
        until = _parse(position.get("backfill_until")) or now
        start = _parse(position.get("backfill_next")) or until - timedelta(
            days=config.backfill_days
        )
        _save(cursor, now, backfill_until=_iso(until))
        await db.commit()
        while start < until:
            end = min(start + window, until)
            await _window(db, client, config, start, end, backfill=True, report=report, now=now)
            _save(cursor, now, backfill_next=_iso(end))
            await db.commit()
            start = end
        _save(cursor, now, backfill_done=True, last_end=_iso(until))
        await db.commit()

    last_end = _parse(cursor.position.get("last_end")) or now
    start = last_end - timedelta(minutes=config.overlap_minutes)
    while start < now:
        end = min(start + window, now)
        await _window(db, client, config, start, end, backfill=False, report=report, now=now)
        _save(cursor, now, last_end=_iso(end), last_success_at=_iso(now))
        await db.commit()
        start = end
    return report


def _lock_id(connector_id: uuid.UUID) -> int:
    digest = hashlib.sha256(f"nvd_sync:{connector_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


async def run_nvd_sync(
    settings: Settings,
    connector_id: uuid.UUID,
    *,
    http: SafeHttpClient | None = None,
    sleep: Sleep = asyncio.sleep,
    clock: Clock = lambda: datetime.now(UTC),
) -> SyncReport | None:
    """Celery entry point. ``http`` replaces the egress client (tests only)."""
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with engine.connect() as lock:
            got = await lock.execute(
                text("SELECT pg_try_advisory_lock(:id)"), {"id": _lock_id(connector_id)}
            )
            if not got.scalar_one():
                log.info("nvd_sync_already_running", connector_id=str(connector_id))
                return None
            try:
                return await _run(settings, engine, connector_id, http, sleep, clock)
            finally:
                await lock.execute(
                    text("SELECT pg_advisory_unlock(:id)"), {"id": _lock_id(connector_id)}
                )
    finally:
        await engine.dispose()


async def _run(
    settings: Settings,
    engine: Any,
    connector_id: uuid.UUID,
    http: SafeHttpClient | None,
    sleep: Sleep,
    clock: Clock,
) -> SyncReport | None:
    async with create_sessionmaker(engine)() as db:
        init_context(db)  # global connector: no workspace context
        connector = await db.get(Connector, connector_id)
        if connector is None or connector.workspace_id is not None or not connector.enabled:
            return None
        if connector.kind != NvdConnector.kind:
            return None
        now = clock()
        try:
            _, ctx = await build_context(db, settings, Vault.from_settings(settings), connector)
            if http is not None:
                ctx.http = http
            config = ctx.config
            if not isinstance(config, NvdConfig):
                return None
            report = await sync_nvd(db, NvdConnector.client(ctx, sleep), connector, config, now)
        except (NvdError, EgressError) as exc:
            await db.rollback()
            connector = await db.get(Connector, connector_id)
            if connector is not None:
                record_health(connector, HealthResult(ok=False, message=f"sync: {exc.code}"), now)
                await db.commit()
            log.warning("nvd_sync_failed", code=exc.code)
            return None
        connector = await db.get(Connector, connector_id)
        if connector is not None:
            record_health(connector, HealthResult(ok=True), now)
            await db.commit()
        log.info("nvd_sync_done", **report.__dict__)
        return report
