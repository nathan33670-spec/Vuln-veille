"""Evaluation bench API (spec 07 §4.6): reference cases, budgeted runs, comparison.

Cases and runs are private to their workspace. A run plays the agent's active version
pinned to a candidate model on the ``ai`` worker; its results stay with it, and the
comparison of two runs can be cited when the preferred engine changes (audit).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.compat import check
from app.ai.agents.models import AIAgent, AIAgentVersion
from app.ai.agents.spec import AgentSpec
from app.ai.evaluation import scoring
from app.ai.evaluation.models import EvalCase, EvalRun
from app.ai.evaluation.schemas import (
    CaseIn,
    CaseOut,
    ComparisonOut,
    RunDetailOut,
    RunIn,
    RunOut,
)
from app.ai.models import AIModel
from app.ai.preferences import usable
from app.audit.service import AuditEntry, record
from app.core.ids import uuid7
from app.core.tasks import TaskQueue
from app.iam.deps import DB, WorkspaceAccess, require_workspace
from app.iam.permissions import Permission

Reader = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_READ))]
Evaluator = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.AI_EVALUATION_RUN))]
RUN_TASK = "ai.evaluation_run"
MAX_CASES = 200


async def _audit(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    action: str,
    target: str,
    **details: object,
) -> None:
    await record(
        db,
        access.principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="ai_evaluation",
            target_id=target,
            workspace_id=access.workspace.id,
            details=details,
        ),
    )


def case_out(case: EvalCase) -> CaseOut:
    return CaseOut(
        id=case.id,
        cve_id=case.cve_id,
        input=case.input,
        expected=case.expected,
        notes=case.notes,
        validated_by=case.validated_by,
        updated_at=case.updated_at,
    )


def run_out(run: EvalRun) -> RunOut:
    return RunOut(
        id=run.id,
        agent_id=run.agent_id,
        model_row_id=run.model_row_id,
        model_id=run.model_id,
        status=run.status,
        max_cost_usd=run.max_cost_usd,
        cases=len(run.case_ids),
        metrics=run.metrics,
        error=run.error,
        queued_at=run.queued_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


async def _case(db: AsyncSession, access: WorkspaceAccess, case_id: uuid.UUID) -> EvalCase:
    case = await db.get(EvalCase, case_id)
    if case is None or case.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return case


async def _run(db: AsyncSession, access: WorkspaceAccess, run_id: uuid.UUID) -> EvalRun:
    run = await db.get(EvalRun, run_id)
    if run is None or run.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return run


def _routes_cases(router: APIRouter) -> None:
    @router.get("/ai-evaluation/cases", response_model=list[CaseOut])
    async def list_cases(access: Reader, db: DB) -> list[CaseOut]:
        rows = await db.execute(
            select(EvalCase)
            .where(EvalCase.workspace_id == access.workspace.id)
            .order_by(EvalCase.cve_id)
        )
        return [case_out(c) for c in rows.scalars()]

    @router.post("/ai-evaluation/cases", response_model=CaseOut, status_code=201)
    async def create_case(body: CaseIn, request: Request, access: Evaluator, db: DB) -> CaseOut:
        case = EvalCase(
            id=uuid7(),
            workspace_id=access.workspace.id,
            cve_id=body.cve_id.upper(),
            input=body.input,
            expected=body.expected,
            notes=body.notes,
            validated_by=access.principal.user_id,
        )
        db.add(case)
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="case_exists") from None
        await _audit(
            db, request, access, "ai_evaluation.case_created", str(case.id), cve=case.cve_id
        )
        await db.commit()
        await db.refresh(case)
        return case_out(case)

    @router.put("/ai-evaluation/cases/{case_id}", response_model=CaseOut)
    async def update_case(
        case_id: uuid.UUID, body: CaseIn, request: Request, access: Evaluator, db: DB
    ) -> CaseOut:
        case = await _case(db, access, case_id)
        case.cve_id, case.input, case.expected = body.cve_id.upper(), body.input, body.expected
        case.notes, case.validated_by = body.notes, access.principal.user_id
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="case_exists") from None
        await _audit(db, request, access, "ai_evaluation.case_updated", str(case.id))
        await db.commit()
        await db.refresh(case)
        return case_out(case)

    @router.delete("/ai-evaluation/cases/{case_id}", status_code=204)
    async def delete_case(case_id: uuid.UUID, request: Request, access: Evaluator, db: DB) -> None:
        case = await _case(db, access, case_id)
        await db.delete(case)
        await _audit(db, request, access, "ai_evaluation.case_deleted", str(case_id))
        await db.commit()


def _routes_runs(router: APIRouter) -> None:
    @router.post("/ai-evaluation/runs", response_model=RunOut, status_code=202)
    async def start_run(body: RunIn, request: Request, access: Evaluator, db: DB) -> RunOut:
        """Manual and budgeted: the cost also counts in the monthly budget."""
        workspace_id = access.workspace.id
        agent = await db.get(AIAgent, body.agent_id)
        if agent is None or agent.workspace_id != workspace_id:
            raise HTTPException(status_code=404, detail="not_found")
        if agent.active_version_id is None:
            raise HTTPException(status_code=422, detail="no_active_version")
        version = await db.get(AIAgentVersion, agent.active_version_id)
        model = await db.get(AIModel, body.model_row_id)
        if model is None or model.workspace_id not in (None, workspace_id):
            raise HTTPException(status_code=404, detail="not_found")
        if not usable(model, workspace_id):
            raise HTTPException(status_code=422, detail="engine_unavailable")
        assert version is not None  # noqa: S101 - foreign key
        compatibility = check(AgentSpec.model_validate(version.spec), model)
        if not compatibility.compatible:
            detail = "engine_incompatible:" + ",".join(compatibility.missing)
            raise HTTPException(status_code=422, detail=detail)
        query = select(EvalCase.id).where(EvalCase.workspace_id == workspace_id)
        if body.case_ids is not None:
            query = query.where(EvalCase.id.in_(body.case_ids))
        case_ids = list((await db.execute(query.order_by(EvalCase.cve_id))).scalars())
        if not case_ids or (body.case_ids is not None and len(case_ids) != len(set(body.case_ids))):
            raise HTTPException(
                status_code=422, detail="no_cases" if not case_ids else "unknown_case"
            )
        run = EvalRun(
            id=uuid7(),
            workspace_id=workspace_id,
            agent_id=agent.id,
            agent_version_id=version.id,
            model_row_id=model.id,
            model_id=model.model_id,
            status="queued",
            max_cost_usd=body.max_cost_usd,
            case_ids=case_ids[:MAX_CASES],
            requested_by=access.principal.user_id,
            queued_at=datetime.now(UTC),
        )
        db.add(run)
        await _audit(
            db,
            request,
            access,
            "ai_evaluation.run_started",
            str(run.id),
            agent_id=str(agent.id),
            model_id=model.model_id,
            max_cost_usd=str(body.max_cost_usd),
            cases=len(run.case_ids),
        )
        await db.commit()
        tasks: TaskQueue = request.app.state.tasks
        tasks.send(RUN_TASK, {"run_id": str(run.id), "workspace_id": str(workspace_id)})
        return run_out(run)

    @router.get("/ai-evaluation/runs", response_model=list[RunOut])
    async def list_runs(access: Reader, db: DB) -> list[RunOut]:
        rows = await db.execute(
            select(EvalRun)
            .where(EvalRun.workspace_id == access.workspace.id)
            .order_by(EvalRun.queued_at.desc())
            .limit(100)
        )
        return [run_out(r) for r in rows.scalars()]

    @router.get("/ai-evaluation/runs/{run_id}", response_model=RunDetailOut)
    async def get_run(run_id: uuid.UUID, access: Reader, db: DB) -> RunDetailOut:
        run = await _run(db, access, run_id)
        return RunDetailOut(**run_out(run).model_dump(), results=run.results)

    @router.get("/ai-evaluation/compare", response_model=ComparisonOut)
    async def compare(
        baseline: uuid.UUID, candidate: uuid.UUID, access: Reader, db: DB
    ) -> ComparisonOut:
        """Current engine against a candidate, metric by metric and case by case."""
        first, second = await _run(db, access, baseline), await _run(db, access, candidate)
        by_case = {r["cve_id"]: r for r in first.results}
        cases = [
            {"cve_id": r["cve_id"], "baseline": by_case.get(r["cve_id"]), "candidate": r}
            for r in second.results
        ]
        return ComparisonOut(
            baseline=run_out(first),
            candidate=run_out(second),
            metrics=scoring.compare(first.metrics, second.metrics),
            cases=cases,
        )


def build_evaluation_router() -> APIRouter:
    router = APIRouter(tags=["ai-evaluation"])
    workspace = APIRouter(prefix="/workspaces/{workspace}")
    _routes_cases(workspace)
    _routes_runs(workspace)
    router.include_router(workspace)
    return router
