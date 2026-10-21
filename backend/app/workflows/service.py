"""Workflow lifecycle shared by the API, the seeding command and tests."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.models import Connector
from app.core.ids import uuid7
from app.iam.permissions import Permission
from app.vault.keys import SecretPurpose
from app.vault.models import Secret
from app.vault.service import Vault, create_secret, replace_value
from app.workflows.base import Reference
from app.workflows.dispatch import activate_triggers
from app.workflows.graph import (
    Compiled,
    ReferenceCheck,
    compile_graph,
    graph_hash,
    validate_graph,
)
from app.workflows.models import Workflow, WorkflowTrigger, WorkflowVersion
from app.workflows.webhooks import new_secret


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
    db: AsyncSession,
    workflow: Workflow,
    version: WorkflowVersion,
    now: datetime,
    *,
    vault: Vault | None = None,
    actor: uuid.UUID | None = None,
) -> dict[str, str]:
    """Activates ``version``; returns the secrets of new webhook triggers (shown once)."""
    compiled = compile_graph(version.graph)
    workflow.active_version_id = version.id
    workflow.status = "active"
    workflow.version += 1
    triggers = await activate_triggers(db, workflow, version, compiled, now)
    created: dict[str, str] = {}
    for trigger in triggers:
        if trigger.type == "webhook" and trigger.webhook_secret_id is None:
            if vault is None or actor is None:
                raise ValueError("webhook triggers need the vault and an actor")
            created[trigger.node_id] = await rotate_webhook_secret(db, vault, trigger, actor)
    await db.flush()
    return created


async def rotate_webhook_secret(
    db: AsyncSession, vault: Vault, trigger: WorkflowTrigger, actor: uuid.UUID
) -> str:
    """A new signing secret (write-only: the plaintext is only returned here)."""
    value = new_secret()
    if trigger.webhook_secret_id is not None:
        current = await db.get(Secret, trigger.webhook_secret_id)
        if current is not None:
            replace_value(vault, current, value, actor)
            return value
    secret = await create_secret(
        db,
        vault,
        workspace_id=trigger.workspace_id,
        purpose=SecretPurpose.WEBHOOK,
        name=f"webhook-{trigger.id}",
        description="Signature du webhook entrant d'un workflow",
        value=value,
        actor=actor,
    )
    trigger.webhook_secret_id = secret.id
    return value
