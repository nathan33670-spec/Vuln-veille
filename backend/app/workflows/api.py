"""Workflow API (spec 02 §9): definitions, versions, runs, approvals, import/export.

Workflows are private to their workspace (RLS and ``workspace_id`` filters). Saving a
version validates the graph against the editor's own permissions and the workspace's
connectors; runs started here are queued to the orchestrator.
"""

import asyncio
import json
import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.service import AuditEntry, record
from app.core.access import public_endpoint
from app.core.errors import ApiError
from app.core.ids import uuid7
from app.core.rate_limit import RateLimiter
from app.core.rls import get_context, init_context, set_context
from app.core.tasks import TaskQueue
from app.iam.deps import DB, WorkspaceAccess, authenticated, require_workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.vault.service import Vault
from app.workflows.base import node_types
from app.workflows.engine import (
    LIMITS,
    TERMINAL_RUN,
    RunRefusedError,
    advance_task,
    decide_approval,
    start_run,
)
from app.workflows.graph import GraphValidationError
from app.workflows.models import (
    NodeRun,
    Workflow,
    WorkflowApproval,
    WorkflowDraft,
    WorkflowRun,
    WorkflowTrigger,
    WorkflowVersion,
)
from app.workflows.schemas import (
    ActivationOut,
    ApprovalDecision,
    ApprovalOut,
    DraftIn,
    DraftOut,
    NodeRunDetailOut,
    NodeRunOut,
    NodeTypeOut,
    RunCreate,
    RunDetailOut,
    RunStarted,
    RunSummaryOut,
    TestNodeIn,
    TriggerOut,
    VersionCreate,
    VersionDetailOut,
    VersionOut,
    WebhookSecretOut,
    WorkflowCreate,
    WorkflowDetailOut,
    WorkflowExport,
    WorkflowImport,
    WorkflowOut,
    WorkflowUpdate,
)
from app.workflows.service import activate, add_version, rotate_webhook_secret, validate_for
from app.workflows.webhooks import (
    MAX_BODY_BYTES,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    enqueue,
    fresh,
    well_formed,
)

Reader = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_READ))]
Editor = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_EDIT))]
Runner = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_RUN))]
MANUAL = "trigger.manual"
NodeIdPath = Annotated[str, Path(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


def now() -> datetime:
    return datetime.now(UTC)


def hook_path(trigger_id: uuid.UUID) -> str:
    return f"/api/v1/hooks/{trigger_id}"


def vault_of(request: Request) -> Vault:
    vault: Vault = request.app.state.vault
    return vault


def tasks_of(request: Request) -> TaskQueue:
    tasks: TaskQueue = request.app.state.tasks
    return tasks


async def _audit(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    action: str,
    target_id: str,
    target_type: str = "workflow",
    **details: object,
) -> None:
    await record(
        db,
        access.principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type=target_type,
            target_id=target_id,
            workspace_id=access.workspace.id,
            details=details,
        ),
    )


async def _workflow(db: AsyncSession, access: WorkspaceAccess, workflow_id: uuid.UUID) -> Workflow:
    workflow = await db.get(Workflow, workflow_id)
    if workflow is None or workflow.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return workflow


async def _run(db: AsyncSession, access: WorkspaceAccess, run_id: uuid.UUID) -> WorkflowRun:
    run = await db.get(WorkflowRun, run_id)
    if run is None or run.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return run


async def _version_numbers(
    db: AsyncSession, ids: set[uuid.UUID | None]
) -> dict[uuid.UUID | None, int]:
    """Version numbers by version id (test runs have none)."""
    known = {i for i in ids if i is not None}
    if not known:
        return {}
    rows = await db.execute(
        select(WorkflowVersion.id, WorkflowVersion.version_no).where(WorkflowVersion.id.in_(known))
    )
    return {row[0]: row[1] for row in rows.all()}


def run_summary(run: WorkflowRun, numbers: dict[uuid.UUID | None, int]) -> RunSummaryOut:
    return RunSummaryOut(
        id=run.id,
        workflow_id=run.workflow_id,
        version_no=numbers.get(run.version_id),
        trigger_type=run.trigger_type,
        status=run.status,
        queued_at=run.queued_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error=run.error,
        stats=run.stats,
    )


def version_out(version: WorkflowVersion) -> VersionOut:
    return VersionOut(
        id=version.id,
        version_no=version.version_no,
        comment=version.comment,
        graph_hash=version.graph_hash,
        created_by=version.created_by,
        created_at=version.created_at,
    )


async def _summaries(db: AsyncSession, workflows: list[Workflow]) -> list[WorkflowOut]:
    ids = [w.id for w in workflows]
    if not ids:
        return []
    latest = dict(
        (
            await db.execute(
                select(WorkflowVersion.workflow_id, func.max(WorkflowVersion.version_no))
                .where(WorkflowVersion.workflow_id.in_(ids))
                .group_by(WorkflowVersion.workflow_id)
            )
        ).all()
    )
    last_runs: dict[uuid.UUID, WorkflowRun] = {}
    rows = await db.execute(
        select(WorkflowRun)
        .where(WorkflowRun.workflow_id.in_(ids), WorkflowRun.mode == "normal")
        .ext(distinct_on(WorkflowRun.workflow_id))
        .order_by(WorkflowRun.workflow_id, WorkflowRun.queued_at.desc())
    )
    for run in rows.scalars():
        last_runs[run.workflow_id] = run
    numbers = await _version_numbers(
        db,
        {*(w.active_version_id for w in workflows), *(r.version_id for r in last_runs.values())},
    )
    return [
        WorkflowOut(
            id=w.id,
            name=w.name,
            description=w.description,
            status=w.status,
            tags=w.tags,
            seed_key=w.seed_key,
            active_version_no=numbers.get(w.active_version_id) if w.active_version_id else None,
            latest_version_no=latest.get(w.id),
            version=w.version,
            updated_at=w.updated_at,
            last_run=run_summary(last_runs[w.id], numbers) if w.id in last_runs else None,
        )
        for w in workflows
    ]


async def _detail(db: AsyncSession, workflow: Workflow) -> WorkflowDetailOut:
    await db.refresh(workflow)  # server-side updated_at after a commit
    (summary,) = await _summaries(db, [workflow])
    versions = list(
        (
            await db.execute(
                select(WorkflowVersion)
                .where(WorkflowVersion.workflow_id == workflow.id)
                .order_by(WorkflowVersion.version_no.desc())
            )
        ).scalars()
    )
    triggers = (
        await db.execute(select(WorkflowTrigger).where(WorkflowTrigger.workflow_id == workflow.id))
    ).scalars()
    return WorkflowDetailOut(
        **summary.model_dump(),
        versions=[version_out(v) for v in versions],
        latest_graph=versions[0].graph if versions else None,
        triggers=[
            TriggerOut(
                id=t.id,
                node_id=t.node_id,
                type=t.type,
                config=t.config,
                next_fire_at=t.next_fire_at,
                enabled=t.enabled,
                webhook_path=hook_path(t.id) if t.type == "webhook" else None,
            )
            for t in triggers
        ],
    )


async def _validated(db: AsyncSession, access: WorkspaceAccess, graph: dict[str, Any]) -> None:
    try:
        await validate_for(db, access.workspace.id, graph, access.workspace.permissions)
    except GraphValidationError as exc:
        raise ApiError(422, "invalid_graph", exc.errors[:100]) from None


async def _create(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    *,
    name: str,
    description: str,
    tags: list[str],
    graph: dict[str, Any] | None,
    comment: str,
    action: str,
) -> Workflow:
    if graph is not None:
        await _validated(db, access, graph)
    workflow = Workflow(
        id=uuid7(),
        workspace_id=access.workspace.id,
        name=name,
        description=description,
        status="draft",
        tags=sorted(set(tags)),
        created_by=access.principal.user_id,
        version=1,
    )
    db.add(workflow)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="name_taken") from None
    if graph is not None:
        await add_version(
            db, workflow, graph, comment=comment, actor=access.principal.user_id, now=now()
        )
    await _audit(db, request, access, action, str(workflow.id), name=name)
    await db.commit()
    return workflow


def node_type_list() -> list[NodeTypeOut]:
    return [
        NodeTypeOut(
            type=t.type,
            version=t.version,
            label=t.label,
            category=t.category,
            queue=t.queue,
            inputs=list(t.inputs),
            outputs=list(t.outputs),
            params_schema=t.Params.model_json_schema(by_alias=True),
            required_permissions=sorted(t.required_permissions),
            uses_egress=t.uses_egress,
            requires_approval_upstream=t.requires_approval_upstream,
            trigger_type=t.trigger_type,
        )
        for t in sorted(node_types().values(), key=lambda t: (t.category, t.type))
        if not t.type.startswith("test.")
    ]


def _routes_workflows(router: APIRouter) -> None:
    @router.get("/workflows", response_model=list[WorkflowOut])
    async def list_workflows(access: Reader, db: DB) -> list[WorkflowOut]:
        rows = await db.execute(
            select(Workflow)
            .where(Workflow.workspace_id == access.workspace.id)
            .order_by(Workflow.name)
        )
        return await _summaries(db, list(rows.scalars()))

    @router.post("/workflows", response_model=WorkflowDetailOut, status_code=201)
    async def create_workflow(
        body: WorkflowCreate, request: Request, access: Editor, db: DB
    ) -> WorkflowDetailOut:
        workflow = await _create(
            db,
            request,
            access,
            name=body.name,
            description=body.description,
            tags=body.tags,
            graph=body.graph,
            comment=body.comment,
            action="workflow.created",
        )
        return await _detail(db, workflow)

    @router.post("/workflows/import", response_model=WorkflowDetailOut, status_code=201)
    async def import_workflow(
        body: WorkflowImport, request: Request, access: Editor, db: DB
    ) -> WorkflowDetailOut:
        workflow = await _create(
            db,
            request,
            access,
            name=body.name,
            description=body.description,
            tags=body.tags,
            graph=body.graph,
            comment="Import",
            action="workflow.imported",
        )
        return await _detail(db, workflow)

    @router.get("/workflows/{workflow_id}", response_model=WorkflowDetailOut)
    async def get_workflow(workflow_id: uuid.UUID, access: Reader, db: DB) -> WorkflowDetailOut:
        return await _detail(db, await _workflow(db, access, workflow_id))

    @router.patch("/workflows/{workflow_id}", response_model=WorkflowDetailOut)
    async def update_workflow(
        workflow_id: uuid.UUID, body: WorkflowUpdate, request: Request, access: Editor, db: DB
    ) -> WorkflowDetailOut:
        workflow = await _workflow(db, access, workflow_id)
        if body.version != workflow.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        changes = body.model_dump(exclude_unset=True, exclude={"version"})
        if changes.get("status") == "active" and workflow.active_version_id is None:
            raise HTTPException(status_code=422, detail="no_active_version")
        for field, value in changes.items():
            setattr(workflow, field, sorted(set(value)) if field == "tags" else value)
        workflow.version += 1
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="name_taken") from None
        await _audit(
            db, request, access, "workflow.updated", str(workflow.id), fields=sorted(changes)
        )
        await db.commit()
        return await _detail(db, workflow)

    @router.get("/workflows/{workflow_id}/export", response_model=WorkflowExport)
    async def export_workflow(workflow_id: uuid.UUID, access: Reader, db: DB) -> WorkflowExport:
        workflow = await _workflow(db, access, workflow_id)
        detail = await _detail(db, workflow)
        if detail.latest_graph is None:
            raise HTTPException(status_code=422, detail="no_version")
        return WorkflowExport(
            name=workflow.name,
            description=workflow.description,
            tags=workflow.tags,
            graph=detail.latest_graph,
        )


def _routes_versions(router: APIRouter) -> None:
    @router.post(
        "/workflows/{workflow_id}/versions", response_model=VersionDetailOut, status_code=201
    )
    async def create_version(
        workflow_id: uuid.UUID, body: VersionCreate, request: Request, access: Editor, db: DB
    ) -> VersionDetailOut:
        workflow = await _workflow(db, access, workflow_id)
        await db.refresh(workflow, with_for_update=True)
        latest = (
            await db.execute(
                select(func.max(WorkflowVersion.version_no)).where(
                    WorkflowVersion.workflow_id == workflow.id
                )
            )
        ).scalar_one()
        if body.base_version_no is not None and body.base_version_no != (latest or 0):
            raise HTTPException(status_code=409, detail="version_conflict")
        await _validated(db, access, body.graph)
        version = await add_version(
            db,
            workflow,
            body.graph,
            comment=body.comment,
            actor=access.principal.user_id,
            now=now(),
        )
        await _audit(
            db,
            request,
            access,
            "workflow.version_created",
            str(workflow.id),
            version_no=version.version_no,
        )
        await db.commit()
        return VersionDetailOut(**version_out(version).model_dump(), graph=version.graph)

    @router.get("/workflows/{workflow_id}/versions/{version_no}", response_model=VersionDetailOut)
    async def get_version(
        workflow_id: uuid.UUID, version_no: int, access: Reader, db: DB
    ) -> VersionDetailOut:
        workflow = await _workflow(db, access, workflow_id)
        version = await _version(db, workflow, version_no)
        return VersionDetailOut(**version_out(version).model_dump(), graph=version.graph)

    @router.post(
        "/workflows/{workflow_id}/versions/{version_no}/activate",
        response_model=ActivationOut,
    )
    async def activate_version(
        workflow_id: uuid.UUID, version_no: int, request: Request, access: Editor, db: DB
    ) -> ActivationOut:
        workflow = await _workflow(db, access, workflow_id)
        await db.refresh(workflow, with_for_update=True)
        version = await _version(db, workflow, version_no)
        # Re-validated with the activating analyst's permissions and current references.
        await _validated(db, access, version.graph)
        secrets = await activate(
            db, workflow, version, now(), vault=vault_of(request), actor=access.principal.user_id
        )
        await _audit(
            db, request, access, "workflow.activated", str(workflow.id), version_no=version_no
        )
        await db.commit()
        detail = await _detail(db, workflow)
        by_node = {t.node_id: t.id for t in detail.triggers}
        return ActivationOut(
            **detail.model_dump(),
            webhook_secrets=[
                WebhookSecretOut(
                    node_id=node_id,
                    trigger_id=by_node[node_id],
                    webhook_path=hook_path(by_node[node_id]),
                    secret=value,
                )
                for node_id, value in secrets.items()
            ],
        )

    @router.post(
        "/workflows/{workflow_id}/triggers/{node_id}/rotate-secret",
        response_model=WebhookSecretOut,
    )
    async def rotate_secret(
        workflow_id: uuid.UUID, node_id: NodeIdPath, request: Request, access: Editor, db: DB
    ) -> WebhookSecretOut:
        workflow = await _workflow(db, access, workflow_id)
        trigger = (
            await db.execute(
                select(WorkflowTrigger).where(
                    WorkflowTrigger.workflow_id == workflow.id,
                    WorkflowTrigger.node_id == node_id,
                    WorkflowTrigger.type == "webhook",
                )
            )
        ).scalar_one_or_none()
        if trigger is None:
            raise HTTPException(status_code=404, detail="not_found")
        value = await rotate_webhook_secret(
            db, vault_of(request), trigger, access.principal.user_id
        )
        await _audit(
            db,
            request,
            access,
            "workflow.webhook_secret_rotated",
            str(workflow.id),
            node_id=node_id,
        )
        await db.commit()
        return WebhookSecretOut(
            node_id=node_id,
            trigger_id=trigger.id,
            webhook_path=hook_path(trigger.id),
            secret=value,
        )


async def _version(db: AsyncSession, workflow: Workflow, version_no: int) -> WorkflowVersion:
    version = (
        await db.execute(
            select(WorkflowVersion).where(
                WorkflowVersion.workflow_id == workflow.id,
                WorkflowVersion.version_no == version_no,
            )
        )
    ).scalar_one_or_none()
    if version is None:
        raise HTTPException(status_code=404, detail="not_found")
    return version


def _routes_runs(router: APIRouter) -> None:
    @router.post("/workflows/{workflow_id}/runs", response_model=RunStarted, status_code=202)
    async def start_manual_run(
        workflow_id: uuid.UUID, body: RunCreate, request: Request, access: Runner, db: DB
    ) -> RunStarted:
        workflow = await _workflow(db, access, workflow_id)
        if workflow.status != "active" or workflow.active_version_id is None:
            raise HTTPException(status_code=409, detail="workflow_not_active")
        version = await db.get(WorkflowVersion, workflow.active_version_id)
        assert version is not None  # noqa: S101 - foreign key
        manual = [n["id"] for n in version.graph.get("nodes", []) if n.get("type") == MANUAL]
        if not manual:
            raise HTTPException(status_code=409, detail="no_manual_trigger")
        key = body.idempotency_key or str(uuid.uuid4())
        try:
            run_id = await start_run(
                db,
                workflow,
                version,
                trigger_node_id=manual[0],
                trigger_type="manual",
                payload=body.input,
                idempotency_key=f"manual:{key}",
                now=now(),
                actor=access.principal.user_id,
            )
        except RunRefusedError as exc:
            raise HTTPException(status_code=422, detail=exc.code) from None
        created = run_id is not None
        if run_id is None:
            run_id = (
                await db.execute(
                    select(WorkflowRun.id).where(
                        WorkflowRun.workflow_id == workflow.id,
                        WorkflowRun.idempotency_key == f"manual:{key}",
                    )
                )
            ).scalar_one()
        else:
            await _audit(
                db,
                request,
                access,
                "workflow.run_started",
                str(run_id),
                "workflow_run",
                workflow_id=str(workflow.id),
            )
        await db.commit()
        if created:
            advance_task(tasks_of(request), run_id, access.workspace.id)
        return RunStarted(run_id=run_id, created=created)

    @router.get("/workflows/{workflow_id}/runs", response_model=list[RunSummaryOut])
    async def list_runs(
        workflow_id: uuid.UUID,
        access: Reader,
        db: DB,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0, le=10000)] = 0,
    ) -> list[RunSummaryOut]:
        workflow = await _workflow(db, access, workflow_id)
        rows = list(
            (
                await db.execute(
                    select(WorkflowRun)
                    .where(WorkflowRun.workflow_id == workflow.id, WorkflowRun.mode == "normal")
                    .order_by(WorkflowRun.queued_at.desc(), WorkflowRun.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
            ).scalars()
        )
        numbers = await _version_numbers(db, {r.version_id for r in rows})
        return [run_summary(r, numbers) for r in rows]

    @router.get("/runs/{run_id}", response_model=RunDetailOut)
    async def get_run(run_id: uuid.UUID, access: Reader, db: DB) -> RunDetailOut:
        run = await _run(db, access, run_id)
        numbers = await _version_numbers(db, {run.version_id})
        node_runs = (
            await db.execute(
                select(NodeRun)
                .where(NodeRun.run_id == run.id)
                .order_by(NodeRun.scheduled_at, NodeRun.attempt)
            )
        ).scalars()
        approvals = (
            await db.execute(select(WorkflowApproval).where(WorkflowApproval.run_id == run.id))
        ).scalars()
        return RunDetailOut(
            **run_summary(run, numbers).model_dump(),
            trigger_node_id=run.trigger_node_id,
            triggered_by=run.triggered_by,
            trigger_payload=run.trigger_payload,
            cancel_requested=run.cancel_requested,
            deadline_at=run.deadline_at,
            node_runs=[_node_run_out(n) for n in node_runs],
            approvals=[
                ApprovalOut(
                    node_id=a.node_id,
                    requested_at=a.requested_at,
                    decision=a.decision,
                    decided_by=a.decided_by,
                    decided_at=a.decided_at,
                    comment=a.comment,
                )
                for a in approvals
            ],
        )

    @router.get("/runs/{run_id}/nodes/{node_id}", response_model=NodeRunDetailOut)
    async def get_node_run(
        run_id: uuid.UUID,
        node_id: NodeIdPath,
        access: Reader,
        db: DB,
    ) -> NodeRunDetailOut:
        run = await _run(db, access, run_id)
        node_run = (
            await db.execute(
                select(NodeRun)
                .where(NodeRun.run_id == run.id, NodeRun.node_id == node_id)
                .order_by(NodeRun.attempt.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if node_run is None:
            raise HTTPException(status_code=404, detail="not_found")
        return NodeRunDetailOut(**_node_run_out(node_run).model_dump(), output=node_run.output)

    @router.post("/runs/{run_id}/cancel", response_model=RunSummaryOut, status_code=202)
    async def cancel_run(
        run_id: uuid.UUID, request: Request, access: Runner, db: DB
    ) -> RunSummaryOut:
        run = await _run(db, access, run_id)
        await db.refresh(run, with_for_update=True)
        if run.status in ("succeeded", "failed", "cancelled", "timed_out"):
            raise HTTPException(status_code=409, detail="run_finished")
        run.cancel_requested = True
        await _audit(db, request, access, "workflow.run_cancelled", str(run.id), "workflow_run")
        await db.commit()
        advance_task(tasks_of(request), run.id, access.workspace.id)
        numbers = await _version_numbers(db, {run.version_id})
        return run_summary(run, numbers)

    @router.post("/runs/{run_id}/approvals/{node_id}", response_model=RunSummaryOut)
    async def decide(
        run_id: uuid.UUID,
        node_id: NodeIdPath,
        body: ApprovalDecision,
        request: Request,
        access: Runner,
        db: DB,
    ) -> RunSummaryOut:
        run = await _run(db, access, run_id)
        await db.refresh(run, with_for_update=True)
        decided = await decide_approval(
            db,
            run,
            node_id,
            approved=body.decision == "approved",
            actor=access.principal.user_id,
            comment=body.comment,
            now=now(),
        )
        if not decided:
            raise HTTPException(status_code=409, detail="nothing_to_decide")
        await _audit(
            db,
            request,
            access,
            "workflow.approval_decided",
            str(run.id),
            "workflow_run",
            node_id=node_id,
            decision=body.decision,
        )
        await db.commit()
        advance_task(tasks_of(request), run.id, access.workspace.id)
        numbers = await _version_numbers(db, {run.version_id})
        return run_summary(run, numbers)


def _node_run_out(node_run: NodeRun) -> NodeRunOut:
    return NodeRunOut(
        node_id=node_run.node_id,
        attempt=node_run.attempt,
        status=node_run.status,
        queue=node_run.queue,
        scheduled_at=node_run.scheduled_at,
        started_at=node_run.started_at,
        finished_at=node_run.finished_at,
        input_count=node_run.input_count,
        output_count=node_run.output_count,
        output_truncated=node_run.output_truncated,
        error=node_run.error,
        logs=node_run.logs,
        metrics=node_run.metrics,
    )


def _route_hooks(router: APIRouter) -> None:
    @router.post("/hooks/{trigger_id}", status_code=202, dependencies=[Depends(public_endpoint)])
    async def incoming_webhook(trigger_id: uuid.UUID, request: Request) -> dict[str, str]:
        """Public, signed: checked here for size, rate and freshness, then by a worker."""
        limiter: RateLimiter = request.app.state.rate_limiter
        ip = request.client.host if request.client else "unknown"
        if not await limiter.hit("webhook_ip", ip, 600, 60) or not await limiter.hit(
            "webhook_trigger", str(trigger_id), 120, 60
        ):
            raise HTTPException(status_code=429, detail="rate_limited")
        timestamp = request.headers.get(TIMESTAMP_HEADER)
        signature = request.headers.get(SIGNATURE_HEADER)
        if not well_formed(timestamp, signature):
            raise HTTPException(status_code=401, detail="signature_required")
        assert timestamp is not None and signature is not None  # noqa: S101, PT018
        if not fresh(timestamp, now()):
            raise HTTPException(status_code=401, detail="stale_timestamp")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="body_too_large")
        enqueue(tasks_of(request), trigger_id, timestamp, signature, bytes(body))
        return {"status": "accepted"}


# Editor (phase 5): drafts, a node tested alone, run events ------------------------

MAX_PINNED = 200
MAX_DRAFT_BYTES = 512 * 1024
EVENTS_SECONDS = 600
POLL_SECONDS = 1.0


async def _latest_version(db: AsyncSession, workflow: Workflow) -> WorkflowVersion | None:
    return (
        await db.execute(
            select(WorkflowVersion)
            .where(WorkflowVersion.workflow_id == workflow.id)
            .order_by(WorkflowVersion.version_no.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _draft_out(db: AsyncSession, access: WorkspaceAccess, draft: WorkflowDraft) -> DraftOut:
    workflow = await db.get(Workflow, draft.workflow_id)
    assert workflow is not None  # noqa: S101 - foreign key
    latest = await _latest_version(db, workflow)
    try:
        await validate_for(db, access.workspace.id, draft.graph, access.workspace.permissions)
        errors: list[dict[str, Any]] = []
    except GraphValidationError as exc:
        errors = exc.errors[:100]
    latest_no = latest.version_no if latest else None
    return DraftOut(
        graph=draft.graph,
        base_version_no=draft.base_version_no,
        latest_version_no=latest_no,
        stale=latest_no is not None and draft.base_version_no != latest_no,
        updated_by=draft.updated_by,
        updated_at=draft.updated_at,
        errors=errors,
    )


def _pinned(inputs: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Analyst-given items, as data: ``{json, meta}`` with a ``pinned`` provenance."""
    out: dict[str, list[dict[str, Any]]] = {}
    for port, entries in inputs.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", port):
            raise HTTPException(status_code=422, detail="invalid_port")
        items = []
        for entry in entries[:MAX_PINNED]:
            data = entry.get("json", entry) if isinstance(entry, dict) else None
            if not isinstance(data, dict):
                raise HTTPException(status_code=422, detail="invalid_item")
            items.append({"json": data, "meta": {"source": "pinned", "trust": "untrusted"}})
        out[port] = items
    if len(json.dumps(out, default=str)) > LIMITS.max_payload_bytes:
        raise HTTPException(status_code=413, detail="payload_too_large")
    return out


def _routes_editor(router: APIRouter) -> None:
    @router.get("/workflows/{workflow_id}/draft", response_model=DraftOut)
    async def get_draft(workflow_id: uuid.UUID, access: Reader, db: DB) -> DraftOut:
        workflow = await _workflow(db, access, workflow_id)
        draft = await db.get(WorkflowDraft, workflow.id)
        if draft is None:
            raise HTTPException(status_code=404, detail="no_draft")
        return await _draft_out(db, access, draft)

    @router.put("/workflows/{workflow_id}/draft", response_model=DraftOut)
    async def put_draft(workflow_id: uuid.UUID, body: DraftIn, access: Editor, db: DB) -> DraftOut:
        """Saved as typed, even if invalid: validation errors come back with it."""
        workflow = await _workflow(db, access, workflow_id)
        if len(json.dumps(body.graph)) > MAX_DRAFT_BYTES:
            raise HTTPException(status_code=413, detail="payload_too_large")
        draft = await db.get(WorkflowDraft, workflow.id, with_for_update=True)
        if draft is None:
            draft = WorkflowDraft(workflow_id=workflow.id, workspace_id=workflow.workspace_id)
            db.add(draft)
        draft.graph, draft.base_version_no = body.graph, body.base_version_no
        draft.updated_by = access.principal.user_id
        await db.commit()
        await db.refresh(draft)
        return await _draft_out(db, access, draft)

    @router.delete("/workflows/{workflow_id}/draft", status_code=204)
    async def delete_draft(workflow_id: uuid.UUID, access: Editor, db: DB) -> None:
        workflow = await _workflow(db, access, workflow_id)
        draft = await db.get(WorkflowDraft, workflow.id)
        if draft is not None:
            await db.delete(draft)
            await db.commit()

    @router.post("/workflows/{workflow_id}/test-node", response_model=RunStarted, status_code=202)
    async def test_node(
        workflow_id: uuid.UUID, body: TestNodeIn, request: Request, access: Editor, db: DB
    ) -> RunStarted:
        """Runs one node alone on pinned inputs, on the worker of its queue: dry-run for
        output nodes, database effects rolled back. The graph is validated against the
        editor's permissions and the workspace's connectors, like a published version."""
        workflow = await _workflow(db, access, workflow_id)
        graph = body.graph
        if graph is None:
            draft = await db.get(WorkflowDraft, workflow.id)
            latest = None if draft else await _latest_version(db, workflow)
            graph = draft.graph if draft else (latest.graph if latest else None)
        if graph is None:
            raise HTTPException(status_code=422, detail="no_graph")
        await _validated(db, access, graph)
        if body.node_id not in {n.get("id") for n in graph.get("nodes", [])}:
            raise HTTPException(status_code=422, detail="unknown_node")
        inputs = _pinned(body.inputs)
        limiter: RateLimiter = request.app.state.rate_limiter
        if not await limiter.hit("test_node", str(access.principal.user_id), 60, 3600):
            raise HTTPException(status_code=429, detail="rate_limited")
        run = WorkflowRun(
            id=uuid7(),
            workspace_id=workflow.workspace_id,
            workflow_id=workflow.id,
            mode="test",
            test_graph=graph,
            test_node_id=body.node_id,
            test_inputs=inputs,
            trigger_type="test",
            trigger_node_id=body.node_id,
            triggered_by=access.principal.user_id,
            trigger_payload={},
            status="queued",
            cancel_requested=False,
            queued_at=now(),
            stats={},
        )
        db.add(run)
        await _audit(
            db, request, access, "workflow.node_tested", str(workflow.id), node_id=body.node_id
        )
        await db.commit()
        advance_task(tasks_of(request), run.id, access.workspace.id)
        return RunStarted(run_id=run.id, created=True)

    @router.get("/runs/{run_id}/events")
    async def run_events(
        run_id: uuid.UUID, request: Request, access: Reader, db: DB
    ) -> StreamingResponse:
        """Server-sent events: one ``node`` event per node state change, ``run`` events,
        until the run ends (or ten minutes). Polls the database, holds no transaction."""
        run = await _run(db, access, run_id)
        context = get_context(db)
        sessions: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
        workspace_id = run.workspace_id

        async def stream() -> AsyncIterator[str]:
            seen: dict[tuple[str, int], tuple[str, int]] = {}
            last_status = ""
            async with sessions() as session:
                init_context(session)
                await set_context(session, **asdict(context))
                for _ in range(int(EVENTS_SECONDS / POLL_SECONDS)):
                    if await request.is_disconnected():
                        return
                    current = await session.get(WorkflowRun, run_id, populate_existing=True)
                    if current is None or current.workspace_id != workspace_id:
                        return
                    rows = await session.execute(
                        select(NodeRun)
                        .where(NodeRun.run_id == run_id)
                        .order_by(NodeRun.scheduled_at)
                    )
                    for node in rows.scalars():
                        state = (node.status, node.output_count)
                        if seen.get((node.node_id, node.attempt)) != state:
                            seen[(node.node_id, node.attempt)] = state
                            yield _sse("node", _node_run_out(node).model_dump(mode="json"))
                    if current.status != last_status:
                        last_status = current.status
                        yield _sse("run", {"status": current.status, "error": current.error})
                    await session.commit()
                    if current.status in TERMINAL_RUN:
                        return
                    await asyncio.sleep(POLL_SECONDS)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"cache-control": "no-store", "x-accel-buffering": "no"},
        )


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def build_workflow_router() -> APIRouter:
    router = APIRouter(tags=["workflows"])
    _route_hooks(router)

    @router.get("/node-types", response_model=list[NodeTypeOut])
    async def list_node_types(
        principal: Annotated[Principal, Depends(authenticated())],
    ) -> list[NodeTypeOut]:
        return node_type_list()

    workspace = APIRouter(prefix="/workspaces/{workspace}")
    _routes_workflows(workspace)
    _routes_versions(workspace)
    _routes_runs(workspace)
    _routes_editor(workspace)
    router.include_router(workspace)
    return router
