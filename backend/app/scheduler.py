"""Scheduler process: fires due triggers at a fixed tick.

Several replicas may run; a PostgreSQL advisory lock elects a single active
leader per tick. Each tick queues the catalogue synchronisations that are due (phase 2);
workflow triggers come in phase 3.
"""

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.catalog.schedule import schedule_syncs
from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import configure_logging, get_logger
from app.core.rls import init_context
from app.core.tasks import CeleryTaskQueue, TaskQueue

# Arbitrary constant identifying the scheduler's advisory lock.
SCHEDULER_LOCK_ID = 0x5656_0001

log = get_logger(__name__)

TickHandler = Callable[[], Awaitable[None]]


async def run_tick(engine: AsyncEngine, handler: TickHandler) -> bool:
    """Runs ``handler`` if this process wins the advisory lock. Returns True if it ran."""
    async with engine.connect() as conn:
        acquired = (
            await conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": SCHEDULER_LOCK_ID})
        ).scalar_one()
        if not acquired:
            return False
        try:
            await handler()
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": SCHEDULER_LOCK_ID})
    return True


def periodic_jobs(engine: AsyncEngine, tasks: TaskQueue) -> TickHandler:
    sessions = create_sessionmaker(engine)

    async def tick() -> None:
        async with sessions() as db:
            init_context(db)
            await schedule_syncs(db, tasks, datetime.now(UTC))

    return tick


async def run(settings: Settings, handler: TickHandler | None = None) -> None:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    handler = handler or periodic_jobs(engine, CeleryTaskQueue())
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    log.info("scheduler_started", tick_seconds=settings.scheduler_tick_seconds)
    try:
        while not stop.is_set():
            try:
                await run_tick(engine, handler)
            except Exception as exc:  # keep the scheduler alive
                log.error("scheduler_tick_failed", exc_info=exc)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=settings.scheduler_tick_seconds)
    finally:
        await engine.dispose()
        log.info("scheduler_stopped")


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    asyncio.run(run(settings))


if __name__ == "__main__":
    main()
