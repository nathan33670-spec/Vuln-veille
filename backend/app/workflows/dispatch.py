"""Trigger dispatch (spec 02 §6, spec 07 §3): activation, schedules, outbox events.

- Activating a version replaces the workflow's ``workflow_triggers`` rows.
- ``fire_schedules`` starts the runs of due cron triggers.
- ``dispatch_outbox`` fans global CVE events (``cve.published``, ``cve.updated``) out
  to every workspace with an active subscribed workflow, and workspace events
  (``vuln.created``) to that workspace's workflows. Each (event, trigger) pair starts
  at most one run (idempotency key); the throughput is bounded by the batch size and
  the per-workflow and per-workspace concurrency limits.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.models import OutboxEvent
from app.core.logging import get_logger
from app.core.rls import set_context
from app.core.tasks import TaskQueue
from app.workflows.engine import RunRefusedError, advance_task, compiled_version, start_run
from app.workflows.graph import Compiled, GraphValidationError
from app.workflows.models import Workflow, WorkflowTrigger, WorkflowVersion
from app.workflows.nodes.triggers import ScheduleParams, TriggerNode, next_fire

log = get_logger(__name__)
OUTBOX_BATCH = 200
SCHEDULE_BATCH = 200
EVENT_TRIGGERS = {"cve.published": "cve_published", "cve.updated": "cve_updated"}
WORKSPACE_EVENTS = frozenset({"vuln.created"})


async def activate_triggers(
    db: AsyncSession,
    workflow: Workflow,
    version: WorkflowVersion,
    compiled: Compiled,
    now: datetime,
) -> list[WorkflowTrigger]:
    """Points the workflow's triggers at ``version``. A trigger keeps its id (the webhook
    URL) and its secret across versions as long as its node id is unchanged."""
    existing = {
        t.node_id: t
        for t in (
            await db.execute(
                select(WorkflowTrigger).where(WorkflowTrigger.workflow_id == workflow.id)
            )
        ).scalars()
    }
    triggers = []
    for node_id in compiled.triggers:
        node_type = compiled.types[node_id]
        params = compiled.params[node_id]
        if not issubclass(node_type, TriggerNode) or not node_type.trigger_type:
            continue
        trigger = existing.pop(node_id, None)
        if trigger is None or trigger.type != node_type.trigger_type:
            if trigger is not None:
                await db.delete(trigger)
                await db.flush()
            trigger = WorkflowTrigger(
                id=uuid.uuid4(),
                workspace_id=workflow.workspace_id,
                workflow_id=workflow.id,
                node_id=node_id,
                type=node_type.trigger_type,
            )
            db.add(trigger)
        trigger.version_id = version.id
        trigger.config = node_type().config(params)
        trigger.enabled = True
        trigger.next_fire_at = (
            next_fire(params.cron, params.timezone, now)
            if isinstance(params, ScheduleParams)
            else None
        )
        triggers.append(trigger)
    for stale in existing.values():
        await db.delete(stale)
    await db.flush()
    return triggers


async def _live(
    db: AsyncSession, trigger: WorkflowTrigger
) -> tuple[Workflow, WorkflowVersion, Compiled] | None:
    workflow = await db.get(Workflow, trigger.workflow_id)
    if workflow is None or workflow.status != "active":
        return None
    if workflow.active_version_id != trigger.version_id:
        return None
    version = await db.get(WorkflowVersion, trigger.version_id)
    if version is None:
        return None
    try:
        return workflow, version, compiled_version(version)
    except GraphValidationError:
        return None


async def fire(
    db: AsyncSession,
    trigger: WorkflowTrigger,
    payload: dict[str, Any],
    idempotency_key: str,
    now: datetime,
    started: list[tuple[uuid.UUID, uuid.UUID]],
) -> bool:
    live = await _live(db, trigger)
    if live is None:
        return False
    workflow, version, compiled = live
    node_type = compiled.types.get(trigger.node_id)
    if node_type is None or not issubclass(node_type, TriggerNode):
        return False
    if not node_type().accepts(compiled.params[trigger.node_id], payload):
        return False
    try:
        run_id = await start_run(
            db,
            workflow,
            version,
            trigger_node_id=trigger.node_id,
            trigger_type=trigger.type,
            payload=payload,
            idempotency_key=idempotency_key,
            now=now,
        )
    except RunRefusedError:
        return False
    if run_id is not None:
        started.append((run_id, workflow.workspace_id))
    return run_id is not None


async def fire_schedules(db: AsyncSession, tasks: TaskQueue, now: datetime) -> int:
    """Cross-workspace (worker role, platform-admin context)."""
    await set_context(db, is_platform_admin=True)
    due = await db.execute(
        select(WorkflowTrigger)
        .where(
            WorkflowTrigger.type == "schedule",
            WorkflowTrigger.enabled,
            WorkflowTrigger.next_fire_at <= now,
        )
        .order_by(WorkflowTrigger.next_fire_at)
        .limit(SCHEDULE_BATCH)
        .with_for_update(skip_locked=True)
    )
    started: list[tuple[uuid.UUID, uuid.UUID]] = []
    for trigger in due.scalars():
        fire_time = trigger.next_fire_at
        assert fire_time is not None  # noqa: S101 - filtered above
        await fire(
            db,
            trigger,
            {"scheduled_at": fire_time.isoformat()},
            f"schedule:{trigger.id}:{fire_time.isoformat()}",
            now,
            started,
        )
        config = trigger.config
        trigger.next_fire_at = next_fire(config["cron"], config["timezone"], now)
    await db.commit()
    for run_id, workspace_id in started:
        advance_task(tasks, run_id, workspace_id)
    return len(started)


async def dispatch_outbox(db: AsyncSession, tasks: TaskQueue, now: datetime) -> int:
    """Cross-workspace (worker role, platform-admin context)."""
    await set_context(db, is_platform_admin=True)
    events = list(
        (
            await db.execute(
                select(OutboxEvent)
                .where(OutboxEvent.dispatched_at.is_(None))
                .order_by(OutboxEvent.id)
                .limit(OUTBOX_BATCH)
                .with_for_update(skip_locked=True)
            )
        ).scalars()
    )
    started: list[tuple[uuid.UUID, uuid.UUID]] = []
    for event in events:
        triggers = await _subscribed(db, event)
        for trigger in triggers:
            await fire(
                db, trigger, event.payload, f"outbox:{event.id}:{trigger.node_id}", now, started
            )
        event.dispatched_at = now
        event.attempts += 1
    await db.commit()
    for run_id, workspace_id in started:
        advance_task(tasks, run_id, workspace_id)
    if events:
        log.info("outbox_dispatched", events=len(events), runs=len(started))
    return len(started)


async def _subscribed(db: AsyncSession, event: OutboxEvent) -> list[WorkflowTrigger]:
    query = select(WorkflowTrigger).where(WorkflowTrigger.enabled)
    if event.type in EVENT_TRIGGERS and event.workspace_id is None:
        query = query.where(WorkflowTrigger.type == EVENT_TRIGGERS[event.type])
    elif event.type in WORKSPACE_EVENTS and event.workspace_id is not None:
        query = query.where(
            WorkflowTrigger.type == "event",
            WorkflowTrigger.workspace_id == event.workspace_id,
            WorkflowTrigger.config["event_type"].astext == event.type,
        )
    else:
        return []
    return list((await db.execute(query.order_by(WorkflowTrigger.workspace_id))).scalars())
