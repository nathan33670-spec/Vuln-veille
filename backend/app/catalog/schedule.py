"""Periodic jobs fired by the scheduler leader (one tick every few seconds)."""

from datetime import datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.models import Connector, ConnectorCursor
from app.connectors.types.nvd import NvdConfig, NvdConnector
from app.core.tasks import TaskQueue

SCHEDULE_STREAM = "schedule"
NVD_SYNC_TASK = "collect.nvd_sync"


async def schedule_nvd(db: AsyncSession, tasks: TaskQueue, now: datetime) -> int:
    """Queues a sync for every enabled NVD connector whose interval has elapsed."""
    connectors = await db.execute(
        select(Connector).where(
            Connector.kind == NvdConnector.kind,
            Connector.workspace_id.is_(None),
            Connector.enabled,
        )
    )
    queued = 0
    for connector in connectors.scalars():
        try:
            config = NvdConfig.model_validate(connector.config)
        except ValidationError:
            continue
        cursor = await db.get(ConnectorCursor, (connector.id, SCHEDULE_STREAM))
        next_run = cursor and cursor.position.get("next_run_at")
        if next_run and datetime.fromisoformat(next_run) > now:
            continue
        upcoming = (now + timedelta(minutes=config.sync_interval_minutes)).isoformat()
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
        tasks.send(NVD_SYNC_TASK, {"connector_id": str(connector.id)})
        queued += 1
    return queued
