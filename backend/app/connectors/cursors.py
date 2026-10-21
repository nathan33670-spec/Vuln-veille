"""Synchronisation cursors (``connector_cursors``), one JSON position per stream."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.models import ConnectorCursor


async def get_cursor(
    db: AsyncSession, connector_id: uuid.UUID, stream: str, now: datetime
) -> ConnectorCursor:
    cursor = await db.get(ConnectorCursor, (connector_id, stream))
    if cursor is None:
        cursor = ConnectorCursor(
            connector_id=connector_id, stream=stream, position={}, updated_at=now
        )
        db.add(cursor)
    return cursor


def save_cursor(cursor: ConnectorCursor, now: datetime, **changes: Any) -> None:
    cursor.position = {**cursor.position, **changes}  # a new dict, so the change is tracked
    cursor.updated_at = now
