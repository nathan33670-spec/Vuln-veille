"""Workflow lifecycle shared by the API, the seeding command and tests."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.models import Connector
from app.core.ids import uuid7
from app.iam.permissions import Permission
from app.workflows.base import Reference
from app.workflows.dispatch import activate_triggers
from app.workflows.graph import (
    Compiled,
    ReferenceCheck,
    compile_graph,
    graph_hash,
    validate_graph,
)
from app.workflows.models import Workflow, WorkflowVersion


def reference_checker(db: AsyncSession, workspace_id: uuid.UUID) -> ReferenceCheck:
    """References must exist in this workspace (or be global connectors)."""

    async def check(reference: Reference) -> bool:
        if reference.kind != "connector":
            return False
        connector = await db.get(Connector, reference.id)
        if connector is None or connector.workspace_id not in (None, workspace_id):
            return False
        if reference.family and connector.family != reference.family:
            return False
        kinds = (reference.kind_of_connector or "").split(",")
        return not reference.kind_of_connector or connector.kind in kinds

    return check


async def validate_for(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    graph: dict[str, Any],
    permissions: frozenset[Permission],
) -> Compiled:
    return await validate_graph(
        graph, permissions=permissions, check_reference=reference_checker(db, workspace_id)
    )


async def add_version(
    db: AsyncSession,
    workflow: Workflow,
    graph: dict[str, Any],
    *,
    comment: str,
    actor: uuid.UUID | None,
    now: datetime,
) -> WorkflowVersion:
    """``graph`` must have been validated by the caller."""
    latest = (
        await db.execute(
            select(func.max(WorkflowVersion.version_no)).where(
                WorkflowVersion.workflow_id == workflow.id
            )
        )
    ).scalar_one()
    version = WorkflowVersion(
        id=uuid7(),
        workspace_id=workflow.workspace_id,
        workflow_id=workflow.id,
        version_no=(latest or 0) + 1,
        graph=graph,
        graph_hash=graph_hash(graph),
        comment=comment,
        created_by=actor,
        created_at=now,
    )
    db.add(version)
    await db.flush()
    return version


async def activate(
    db: AsyncSession, workflow: Workflow, version: WorkflowVersion, now: datetime
) -> None:
    compiled = compile_graph(version.graph)
    workflow.active_version_id = version.id
    workflow.status = "active"
    workflow.version += 1
    await activate_triggers(db, workflow, version, compiled, now)
    await db.flush()
