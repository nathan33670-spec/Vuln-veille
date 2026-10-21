"""Workflow API (spec 02 §9): definitions, versions, runs, approvals, import/export.

Workflows are private to their workspace (RLS and ``workspace_id`` filters). Saving a
version validates the graph against the editor's own permissions and the workspace's
connectors; runs started here are queued to the orchestrator.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.core.errors import ApiError
from app.core.ids import uuid7
from app.core.tasks import TaskQueue
from app.iam.deps import DB, WorkspaceAccess, authenticated, require_workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.workflows.base import node_types
from app.workflows.engine import RunRefusedError, advance_task, decide_approval, start_run
from app.workflows.graph import GraphValidationError
from app.workflows.models import (
    NodeRun,
    Workflow,
    WorkflowApproval,
    WorkflowRun,
    WorkflowTrigger,
    WorkflowVersion,
)
from app.workflows.schemas import (
    ApprovalDecision,
    ApprovalOut,
    NodeRunDetailOut,
    NodeRunOut,
    NodeTypeOut,
    RunCreate,
    RunDetailOut,
    RunStarted,
    RunSummaryOut,
    TriggerOut,
    VersionCreate,
    VersionDetailOut,
    VersionOut,
    WorkflowCreate,
    WorkflowDetailOut,
    WorkflowExport,
    WorkflowImport,
    WorkflowOut,
    WorkflowUpdate,
)
from app.workflows.service import activate, add_version, validate_for

Reader = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_READ))]
Editor = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_EDIT))]
Runner = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_RUN))]
MANUAL = "trigger.manual"
NodeIdPath = Annotated[str, Path(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


def now() -> datetime:
    return datetime.now(UTC)


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


async def _version_numbers(db: AsyncSession, ids: set[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not ids:
        return {}
    rows = await db.execute(
        select(WorkflowVersion.id, WorkflowVersion.version_no).where(WorkflowVersion.id.in_(ids))
    )
    return dict(rows.all())


def run_summary(run: WorkflowRun, numbers: dict[uuid.UUID, int]) -> RunSummaryOut:
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
        .where(WorkflowRun.workflow_id.in_(ids))
        .ext(distinct_on(WorkflowRun.workflow_id))
        .order_by(WorkflowRun.workflow_id, WorkflowRun.queued_at.desc())
    )
    for run in rows.scalars():
        last_runs[run.workflow_id] = run
    numbers = await _version_numbers(
        db,
        {w.active_version_id for w in workflows if w.active_version_id}
        | {r.version_id for r in last_runs.values()},
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
                node_id=t.node_id,
                type=t.type,
                config=t.config,
                next_fire_at=t.next_fire_at,
                enabled=t.enabled,
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
        response_model=WorkflowDetailOut,
    )
    async def activate_version(
        workflow_id: uuid.UUID, version_no: int, request: Request, access: Editor, db: DB
    ) -> WorkflowDetailOut:
        workflow = await _workflow(db, access, workflow_id)
        await db.refresh(workflow, with_for_update=True)
        version = await _version(db, workflow, version_no)
        # Re-validated with the activating analyst's permissions and current references.
        await _validated(db, access, version.graph)
        await activate(db, workflow, version, now())
        await _audit(
            db, request, access, "workflow.activated", str(workflow.id), version_no=version_no
        )
        await db.commit()
        return await _detail(db, workflow)


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
                    .where(WorkflowRun.workflow_id == workflow.id)
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


def build_workflow_router() -> APIRouter:
    router = APIRouter(tags=["workflows"])

    @router.get("/node-types", response_model=list[NodeTypeOut])
    async def list_node_types(
        principal: Annotated[Principal, Depends(authenticated())],
    ) -> list[NodeTypeOut]:
        return node_type_list()

    workspace = APIRouter(prefix="/workspaces/{workspace}")
    _routes_workflows(workspace)
    _routes_versions(workspace)
    _routes_runs(workspace)
    router.include_router(workspace)
    return router
