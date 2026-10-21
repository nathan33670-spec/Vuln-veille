"""Agent API (spec 03 §2, §8, §9): versioned agents, test runs and their traces,
monthly budget, and the compatibility report shown before the engine changes.

Agents are private to their workspace (RLS and ``workspace_id`` filters). Saving a
version checks it against the workspace: its connectors, the tools they enable, and
the pinned engine. Test runs are queued to the ``ai`` worker; every write is audited.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents import budget
from app.ai.agents.compat import check
from app.ai.agents.models import AgentRun, AgentStep, AIAgent, AIAgentVersion, LlmBudget, LlmSpend
from app.ai.agents.schemas import (
    AgentCompatibilityOut,
    AgentCreate,
    AgentDetailOut,
    AgentOut,
    AgentRunDetailOut,
    AgentRunOut,
    AgentRunQueued,
    AgentStepOut,
    AgentTestIn,
    AgentUpdate,
    AgentVersionCreate,
    AgentVersionDetailOut,
    AgentVersionOut,
    BudgetIn,
    BudgetOut,
    CompatibilityReportOut,
    NeedOut,
    SpendOut,
)
from app.ai.agents.spec import AgentSpec
from app.ai.agents.tools import TOOLS
from app.ai.models import AIModel
from app.ai.preferences import usable
from app.audit.service import AuditEntry, record
from app.connectors.models import Connector
from app.core.ids import uuid7
from app.core.rate_limit import RateLimiter
from app.core.tasks import TaskQueue
from app.iam.deps import DB, WorkspaceAccess, require_workspace
from app.iam.permissions import Permission

Reader = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_READ))]
Manager = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.AI_AGENT_MANAGE))]
Tester = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.AI_AGENT_RUN))]
EngineAdmin = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.AI_ENGINE_MANAGE))]
RUN_TASK = "ai.agent_run"
MAX_INPUT_BYTES = 64 * 1024
TESTS_PER_HOUR = 30
HISTORY_MONTHS = 6


def now() -> datetime:
    return datetime.now(UTC)


async def _audit(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    action: str,
    target_id: str,
    target_type: str = "ai_agent",
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


async def _agent(db: AsyncSession, access: WorkspaceAccess, agent_id: uuid.UUID) -> AIAgent:
    agent = await db.get(AIAgent, agent_id)
    if agent is None or agent.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return agent


async def _versions(db: AsyncSession, agent_id: uuid.UUID) -> list[AIAgentVersion]:
    rows = await db.execute(
        select(AIAgentVersion)
        .where(AIAgentVersion.agent_id == agent_id)
        .order_by(AIAgentVersion.version_no.desc())
    )
    return list(rows.scalars())


async def _version(db: AsyncSession, agent: AIAgent, version_no: int) -> AIAgentVersion:
    version = (
        await db.execute(
            select(AIAgentVersion).where(
                AIAgentVersion.agent_id == agent.id, AIAgentVersion.version_no == version_no
            )
        )
    ).scalar_one_or_none()
    if version is None:
        raise HTTPException(status_code=404, detail="not_found")
    return version


def version_out(version: AIAgentVersion) -> AgentVersionOut:
    return AgentVersionOut(
        id=version.id,
        version_no=version.version_no,
        comment=version.comment,
        created_by=version.created_by,
        created_at=version.created_at,
    )


def _summary(agent: AIAgent, active: AIAgentVersion | None) -> AgentOut:
    spec = active.spec if active else {}
    return AgentOut(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        enabled=agent.enabled,
        preset=agent.preset,
        version=agent.version,
        active_version_no=active.version_no if active else None,
        engine_mode=spec.get("engine_mode") if active else None,
        tools=list(spec.get("tools", [])),
        updated_at=agent.updated_at,
    )


async def _detail(db: AsyncSession, agent: AIAgent) -> AgentDetailOut:
    await db.refresh(agent)
    versions = await _versions(db, agent.id)
    active = next((v for v in versions if v.id == agent.active_version_id), None)
    return AgentDetailOut(
        **_summary(agent, active).model_dump(),
        active_spec=active.spec if active else None,
        versions=[version_out(v) for v in versions],
    )


async def validate_spec(db: AsyncSession, workspace_id: uuid.UUID, spec: AgentSpec) -> None:
    """The spec against the workspace: connectors, the tools they enable, pinned engine."""
    connectors: list[Connector] = []
    if spec.allowed_connectors:
        rows = await db.execute(select(Connector).where(Connector.id.in_(spec.allowed_connectors)))
        connectors = [
            c
            for c in rows.scalars()
            if c.workspace_id in (None, workspace_id) and c.family == "source"
        ]
        if len(connectors) != len(spec.allowed_connectors):
            raise HTTPException(status_code=422, detail="unknown_connector")
    kinds = {c.kind for c in connectors}
    for name in spec.tools:
        needed = TOOLS[name].connector_kinds
        if needed and not kinds & set(needed):
            raise HTTPException(status_code=422, detail=f"tool_without_connector:{name}")
    if spec.pinned is not None:
        model = await db.get(AIModel, spec.pinned)
        if model is None or not usable(model, workspace_id):
            raise HTTPException(status_code=422, detail="engine_unavailable")
        compatibility = check(spec, model)
        if not compatibility.compatible:
            detail = "engine_incompatible:" + ",".join(compatibility.missing)
            raise HTTPException(status_code=422, detail=detail)


async def _add_version(
    db: AsyncSession, agent: AIAgent, spec: AgentSpec, comment: str, actor: uuid.UUID
) -> AIAgentVersion:
    latest = (
        await db.execute(
            select(func.max(AIAgentVersion.version_no)).where(AIAgentVersion.agent_id == agent.id)
        )
    ).scalar_one()
    version = AIAgentVersion(
        id=uuid7(),
        workspace_id=agent.workspace_id,
        agent_id=agent.id,
        version_no=(latest or 0) + 1,
        spec=spec.model_dump(mode="json"),
        comment=comment,
        created_by=actor,
        created_at=now(),
    )
    db.add(version)
    await db.flush()
    agent.active_version_id = version.id
    agent.version += 1
    return version


def _routes_agents(router: APIRouter) -> None:
    @router.get("/agents", response_model=list[AgentOut])
    async def list_agents(access: Reader, db: DB) -> list[AgentOut]:
        agents = list(
            (
                await db.execute(
                    select(AIAgent)
                    .where(AIAgent.workspace_id == access.workspace.id)
                    .order_by(AIAgent.name)
                )
            ).scalars()
        )
        ids = [a.active_version_id for a in agents if a.active_version_id]
        active = {
            v.id: v
            for v in (
                await db.execute(select(AIAgentVersion).where(AIAgentVersion.id.in_(ids)))
            ).scalars()
        }
        return [
            _summary(a, active.get(a.active_version_id) if a.active_version_id else None)
            for a in agents
        ]

    @router.post("/agents", response_model=AgentDetailOut, status_code=201)
    async def create_agent(
        body: AgentCreate, request: Request, access: Manager, db: DB
    ) -> AgentDetailOut:
        await validate_spec(db, access.workspace.id, body.spec)
        agent = AIAgent(
            id=uuid7(),
            workspace_id=access.workspace.id,
            name=body.name,
            description=body.description,
            created_by=access.principal.user_id,
            version=0,
        )
        db.add(agent)
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="name_taken") from None
        version = await _add_version(db, agent, body.spec, body.comment, access.principal.user_id)
        await _audit(db, request, access, "ai_agent.created", str(agent.id), name=agent.name)
        await _audit(db, request, access, "ai_agent.version_created", str(agent.id), version_no=1)
        await db.commit()
        assert version.version_no == 1  # noqa: S101 - new agent
        return await _detail(db, agent)

    @router.get("/agents/{agent_id}", response_model=AgentDetailOut)
    async def get_agent(agent_id: uuid.UUID, access: Reader, db: DB) -> AgentDetailOut:
        return await _detail(db, await _agent(db, access, agent_id))

    @router.patch("/agents/{agent_id}", response_model=AgentDetailOut)
    async def update_agent(
        agent_id: uuid.UUID, body: AgentUpdate, request: Request, access: Manager, db: DB
    ) -> AgentDetailOut:
        agent = await _agent(db, access, agent_id)
        await db.refresh(agent, with_for_update=True)
        if body.version != agent.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        changes = body.model_dump(exclude_unset=True, exclude={"version"})
        for key, value in changes.items():
            setattr(agent, key, value)
        agent.version += 1
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="name_taken") from None
        await _audit(db, request, access, "ai_agent.updated", str(agent.id), fields=sorted(changes))
        await db.commit()
        return await _detail(db, agent)

    @router.post(
        "/agents/{agent_id}/versions", response_model=AgentVersionDetailOut, status_code=201
    )
    async def create_version(
        agent_id: uuid.UUID, body: AgentVersionCreate, request: Request, access: Manager, db: DB
    ) -> AgentVersionDetailOut:
        agent = await _agent(db, access, agent_id)
        await db.refresh(agent, with_for_update=True)
        latest = (
            await db.execute(
                select(func.max(AIAgentVersion.version_no)).where(
                    AIAgentVersion.agent_id == agent.id
                )
            )
        ).scalar_one()
        if body.base_version_no is not None and body.base_version_no != (latest or 0):
            raise HTTPException(status_code=409, detail="version_conflict")
        await validate_spec(db, access.workspace.id, body.spec)
        version = await _add_version(db, agent, body.spec, body.comment, access.principal.user_id)
        await _audit(
            db,
            request,
            access,
            "ai_agent.version_created",
            str(agent.id),
            version_no=version.version_no,
        )
        await db.commit()
        return AgentVersionDetailOut(**version_out(version).model_dump(), spec=version.spec)

    @router.get("/agents/{agent_id}/versions/{version_no}", response_model=AgentVersionDetailOut)
    async def get_version(
        agent_id: uuid.UUID, version_no: int, access: Reader, db: DB
    ) -> AgentVersionDetailOut:
        version = await _version(db, await _agent(db, access, agent_id), version_no)
        return AgentVersionDetailOut(**version_out(version).model_dump(), spec=version.spec)

    @router.post("/agents/{agent_id}/versions/{version_no}/activate", response_model=AgentDetailOut)
    async def activate_version(
        agent_id: uuid.UUID, version_no: int, request: Request, access: Manager, db: DB
    ) -> AgentDetailOut:
        """Rolls back (or forward) to an existing version, checked again first."""
        agent = await _agent(db, access, agent_id)
        await db.refresh(agent, with_for_update=True)
        version = await _version(db, agent, version_no)
        await validate_spec(db, access.workspace.id, AgentSpec.model_validate(version.spec))
        agent.active_version_id = version.id
        agent.version += 1
        await _audit(
            db, request, access, "ai_agent.version_activated", str(agent.id), version_no=version_no
        )
        await db.commit()
        return await _detail(db, agent)


def _run_out(run: AgentRun, numbers: dict[uuid.UUID, int]) -> AgentRunOut:
    return AgentRunOut(
        id=run.id,
        agent_id=run.agent_id,
        task=run.task,
        agent_version_no=numbers.get(run.agent_version_id) if run.agent_version_id else None,
        context_type=run.context_type,
        context_id=run.context_id,
        status=run.status,
        engine_kind=run.engine_kind,
        model_requested=run.model_requested,
        model_served=run.model_served,
        turns=run.turns,
        tool_calls=run.tool_calls,
        input_tokens=run.input_tokens,
        output_tokens=run.output_tokens,
        cost_estimate_usd=run.cost_estimate_usd,
        injection_flag_count=len(run.injection_flags),
        error=run.error,
        refusal_category=run.refusal_category,
        queued_at=run.queued_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


async def _numbers(db: AsyncSession, ids: set[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not ids:
        return {}
    rows = await db.execute(
        select(AIAgentVersion.id, AIAgentVersion.version_no).where(AIAgentVersion.id.in_(ids))
    )
    return {row[0]: row[1] for row in rows.all()}


def _routes_runs(router: APIRouter) -> None:
    @router.post("/agents/{agent_id}/test", response_model=AgentRunQueued, status_code=202)
    async def test_agent(
        agent_id: uuid.UUID, body: AgentTestIn, request: Request, access: Tester, db: DB
    ) -> AgentRunQueued:
        """Sandbox run on a CVE or a text: queued, traced like any run."""
        if len(json.dumps(body.input)) > MAX_INPUT_BYTES:
            raise HTTPException(status_code=413, detail="input_too_large")
        limiter: RateLimiter = request.app.state.rate_limiter
        if not await limiter.hit("agent_test", str(access.principal.user_id), TESTS_PER_HOUR, 3600):
            raise HTTPException(status_code=429, detail="rate_limited")
        agent = await _agent(db, access, agent_id)
        if body.version_no is not None:
            version_id = (await _version(db, agent, body.version_no)).id
        elif agent.active_version_id is not None:
            version_id = agent.active_version_id
        else:
            raise HTTPException(status_code=422, detail="no_active_version")
        run = AgentRun(
            id=uuid7(),
            workspace_id=access.workspace.id,
            agent_id=agent.id,
            agent_version_id=version_id,
            context_type="test",
            requested_by=access.principal.user_id,
            input=body.input,
            status="queued",
            queued_at=now(),
        )
        db.add(run)
        await _audit(
            db, request, access, "ai_agent.test_started", str(agent.id), run_id=str(run.id)
        )
        await db.commit()
        tasks: TaskQueue = request.app.state.tasks
        tasks.send(RUN_TASK, {"run_id": str(run.id), "workspace_id": str(access.workspace.id)})
        return AgentRunQueued(run_id=run.id, status="queued")

    @router.get("/agent-runs", response_model=list[AgentRunOut])
    async def list_runs(
        access: Reader,
        db: DB,
        agent_id: uuid.UUID | None = None,
        context_type: str | None = Query(default=None, max_length=20),
        context_id: str | None = Query(default=None, max_length=100),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> list[AgentRunOut]:
        query = select(AgentRun).where(AgentRun.workspace_id == access.workspace.id)
        if agent_id is not None:
            query = query.where(AgentRun.agent_id == agent_id)
        if context_type is not None:
            query = query.where(AgentRun.context_type == context_type)
        if context_id is not None:
            query = query.where(AgentRun.context_id == context_id)
        runs = list(
            (await db.execute(query.order_by(AgentRun.queued_at.desc()).limit(limit))).scalars()
        )
        numbers = await _numbers(db, {r.agent_version_id for r in runs if r.agent_version_id})
        return [_run_out(r, numbers) for r in runs]

    @router.get("/agent-runs/{run_id}", response_model=AgentRunDetailOut)
    async def get_run(run_id: uuid.UUID, access: Reader, db: DB) -> AgentRunDetailOut:
        run = await db.get(AgentRun, run_id)
        if run is None or run.workspace_id != access.workspace.id:
            raise HTTPException(status_code=404, detail="not_found")
        steps = (
            await db.execute(
                select(AgentStep).where(AgentStep.agent_run_id == run.id).order_by(AgentStep.seq)
            )
        ).scalars()
        numbers = await _numbers(db, {run.agent_version_id} if run.agent_version_id else set())
        return AgentRunDetailOut(
            **_run_out(run, numbers).model_dump(),
            input=run.input,
            output=run.output,
            sources=run.sources,
            injection_flags=run.injection_flags,
            cache_read_tokens=run.cache_read_tokens,
            cache_write_tokens=run.cache_write_tokens,
            steps=[
                AgentStepOut(seq=s.seq, type=s.type, payload=s.payload, created_at=s.created_at)
                for s in steps
            ],
        )


async def _budget_view(db: AsyncSession, workspace_id: uuid.UUID) -> BudgetOut:
    current = now()
    state = await budget.state(db, workspace_id, current)
    history = list(
        (
            await db.execute(
                select(LlmSpend)
                .where(LlmSpend.workspace_id == workspace_id)
                .order_by(LlmSpend.period.desc())
                .limit(HISTORY_MONTHS)
            )
        ).scalars()
    )
    period = budget.period_of(current)
    this_month = next((h for h in history if h.period == period), None)
    return BudgetOut(
        monthly_limit_usd=state.limit_usd,
        hard_stop=state.hard_stop,
        period=period,
        spent_usd=state.spent_usd,
        percent=state.percent,
        exhausted=state.exhausted,
        alerts_sent=sorted(this_month.alerts_sent) if this_month else [],
        history=[
            SpendOut(
                period=h.period,
                spent_usd=h.spent_usd,
                input_tokens=h.input_tokens,
                output_tokens=h.output_tokens,
                calls=h.calls,
            )
            for h in history
        ],
    )


def _routes_budget(router: APIRouter) -> None:
    @router.get("/ai-budget", response_model=BudgetOut)
    async def get_budget(access: Reader, db: DB) -> BudgetOut:
        return await _budget_view(db, access.workspace.id)

    @router.put("/ai-budget", response_model=BudgetOut)
    async def put_budget(
        body: BudgetIn, request: Request, access: EngineAdmin, db: DB
    ) -> BudgetOut:
        row = await db.get(LlmBudget, access.workspace.id, with_for_update=True)
        if row is None:
            row = LlmBudget(workspace_id=access.workspace.id)
            db.add(row)
        row.monthly_limit_usd, row.hard_stop = body.monthly_limit_usd, body.hard_stop
        row.updated_by = access.principal.user_id
        await _audit(
            db,
            request,
            access,
            "ai_budget.updated",
            str(access.workspace.id),
            target_type="llm_budget",
            monthly_limit_usd=str(body.monthly_limit_usd),
            hard_stop=body.hard_stop,
        )
        await db.commit()
        return await _budget_view(db, access.workspace.id)

    @router.get("/ai-engine/compatibility", response_model=CompatibilityReportOut)
    async def compatibility(
        model_row_id: uuid.UUID, access: EngineAdmin, db: DB
    ) -> CompatibilityReportOut:
        """Before changing the workspace's preferred engine: which agents it would break.
        Pinned agents are listed as unaffected."""
        model = await db.get(AIModel, model_row_id)
        if model is None or model.workspace_id not in (None, access.workspace.id):
            raise HTTPException(status_code=404, detail="not_found")
        rows = await db.execute(
            select(AIAgent, AIAgentVersion)
            .join(AIAgentVersion, AIAgentVersion.id == AIAgent.active_version_id)
            .where(AIAgent.workspace_id == access.workspace.id, AIAgent.enabled.is_(True))
            .order_by(AIAgent.name)
        )
        agents: list[AgentCompatibilityOut] = []
        for agent, version in rows.all():
            spec = AgentSpec.model_validate(version.spec)
            result = check(spec, model)
            affected = spec.pinned is None
            agents.append(
                AgentCompatibilityOut(
                    agent_id=agent.id,
                    name=agent.name,
                    engine_mode=spec.engine_mode,
                    affected=affected,
                    compatible=result.compatible,
                    needs=[
                        NeedOut(name=n.name, level=n.level, detail=n.detail) for n in result.needs
                    ],
                )
            )
        return CompatibilityReportOut(
            model_row_id=model.id,
            model_id=model.model_id,
            compatible=all(a.compatible for a in agents if a.affected),
            agents=agents,
        )


def build_agent_router() -> APIRouter:
    router = APIRouter(tags=["ai-agents"])
    workspace = APIRouter(prefix="/workspaces/{workspace}")
    _routes_agents(workspace)
    _routes_runs(workspace)
    _routes_budget(workspace)
    router.include_router(workspace)
    return router
