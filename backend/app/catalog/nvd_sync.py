"""NVD synchronisation (spec 07 §3.1), run by the ``collect`` worker.

- Initial catch-up over ``backfill_days``, in windows of at most 120 days, with no
  events (it would launch hundreds of investigations at once).
- Then incremental windows from the end of the last successful one, minus a small
  overlap, to now. The cursor moves after each completed window: a failure resumes
  where it stopped and no window is lost; replays detect nothing new.
- Each page is committed with its change history and outbox events.
Run through ``app.connectors.jobs.run_sync`` (lock, health, Celery task).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.nvd_parse import NvdParseError, parse_cve
from app.catalog.store import upsert_cve
from app.connectors.cursors import get_cursor, save_cursor
from app.connectors.types.nvd import NvdClient, NvdConfig

STREAM = "cves"


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
    db: AsyncSession,
    client: NvdClient,
    connector_id: uuid.UUID,
    config: NvdConfig,
    now: datetime,
) -> SyncReport:
    report = SyncReport()
    window = timedelta(days=config.window_days)
    cursor = await get_cursor(db, connector_id, STREAM, now)
    position = cursor.position

    if not position.get("backfill_done"):
        until = _parse(position.get("backfill_until")) or now
        start = _parse(position.get("backfill_next")) or until - timedelta(
            days=config.backfill_days
        )
        save_cursor(cursor, now, backfill_until=_iso(until))
        await db.commit()
        while start < until:
            end = min(start + window, until)
            await _window(db, client, config, start, end, backfill=True, report=report, now=now)
            save_cursor(cursor, now, backfill_next=_iso(end))
            await db.commit()
            start = end
        save_cursor(cursor, now, backfill_done=True, last_end=_iso(until))
        await db.commit()

    last_end = _parse(cursor.position.get("last_end")) or now
    start = last_end - timedelta(minutes=config.overlap_minutes)
    while start < now:
        end = min(start + window, now)
        await _window(db, client, config, start, end, backfill=False, report=report, now=now)
        save_cursor(cursor, now, last_end=_iso(end), last_success_at=_iso(now))
        await db.commit()
        start = end
    return report
