"""Creating a push: shared by the « Pousser » action and the ``publish.api`` node."""

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import Family
from app.connectors.models import Connector
from app.core.ids import uuid7
from app.publish.context import Publication, PublishError
from app.publish.models import PublicationTarget, PushRecord

IN_FLIGHT = ("queued", "sending", "retrying")


async def push_target(
    db: AsyncSession, workspace_id: uuid.UUID, connector_id: uuid.UUID
) -> Connector:
    """An enabled publication connector of the workspace, or a global one (Q40)."""
    connector = await db.get(Connector, connector_id)
    if (
        connector is None
        or connector.family != Family.PUBLISH
        or connector.workspace_id not in (workspace_id, None)
    ):
        raise PublishError("connector_not_found")
    if not connector.enabled:
        raise PublishError("connector_disabled")
    return connector


async def first_push(db: AsyncSession, bulletin_id: uuid.UUID, connector_id: uuid.UUID) -> bool:
    """No successful push yet of this bulletin to this connector (Q43: second factor)."""
    target = await db.get(PublicationTarget, (bulletin_id, connector_id))
    return target is None or target.first_pushed_at is None


async def queue_push(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    connector: Connector,
    publication: Publication | None,
    *,
    origin: str,
    requested_by: uuid.UUID | None,
    now: datetime,
    node_run_id: uuid.UUID | None = None,
) -> PushRecord:
    """A queued push; ``publication=None`` is a connection test on the example."""
    if publication is not None:
        busy = await db.execute(
            select(PushRecord.id).where(
                PushRecord.bulletin_id == publication.bulletin.id,
                PushRecord.connector_id == connector.id,
                PushRecord.status.in_(IN_FLIGHT),
            )
        )
        if busy.first() is not None:
            raise PublishError("push_in_progress")
    record = PushRecord(
        id=uuid7(),
        workspace_id=workspace_id,
        bulletin_id=publication.bulletin.id if publication else None,
        connector_id=connector.id,
        connector_version=connector.version,
        revision_id=publication.revision.id if publication else None,
        rev_no=publication.revision.rev_no if publication else None,
        is_test=publication is None,
        origin=origin,
        requested_by=requested_by,
        node_run_id=node_run_id,
        status="queued",
        attempts=0,
        created_at=now,
    )
    db.add(record)
    return record
