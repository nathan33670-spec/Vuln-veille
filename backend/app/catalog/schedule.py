"""Periodic jobs fired by the scheduler leader (one tick every few seconds)."""

from datetime import datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import registered
from app.connectors.jobs import SYNC_TASK
from app.connectors.models import Connector, ConnectorCursor
from app.core.tasks import TaskQueue

SCHEDULE_STREAM = "schedule"


async def schedule_syncs(db: AsyncSession, tasks: TaskQueue, now: datetime) -> int:
    """Queues a sync for every enabled global connector whose interval has elapsed."""
    synced = {kind: t for kind, t in registered().items() if t.syncs}
    connectors = await db.execute(
        select(Connector).where(
            Connector.kind.in_(synced), Connector.workspace_id.is_(None), Connector.enabled
        )
    )
    queued = 0
    for connector in connectors.scalars():
        try:
            config = synced[connector.kind].config_model.model_validate(connector.config)
        except ValidationError:
            continue
        interval = timedelta(minutes=config.model_dump()["sync_interval_minutes"])
        cursor = await db.get(ConnectorCursor, (connector.id, SCHEDULE_STREAM))
        next_run = cursor and cursor.position.get("next_run_at")
        if next_run and datetime.fromisoformat(next_run) > now:
            continue
        upcoming = (now + interval).isoformat()
        if cursor is None:
            db.add(
                ConnectorCursor(
                    connector_id=connector.id,
                    stream=SCHEDULE_STREAM,
                    position={"next_run_at": upcoming},
                    updated_at=now,
                )
            )
        else:
            cursor.position = {**cursor.position, "next_run_at": upcoming}
            cursor.updated_at = now
        await db.commit()  # recorded before sending: a crash skips a run, never doubles it
        tasks.send(SYNC_TASK, {"connector_id": str(connector.id)})
        queued += 1
    return queued
