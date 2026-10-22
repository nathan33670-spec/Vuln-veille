"""Playing an evaluation run, in the ``ai`` worker (``ai.evaluation_run``).

The agent version's configuration is pinned to the candidate model, so the run tests
exactly what the agents would do after a switch. Each case is an ordinary traced agent
run (context ``evaluation``), counted in the workspace's monthly budget; the bench
stops once its own budget is spent. Results are committed case by case.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.agents.invoke import WorkerAgents
from app.ai.agents.models import AIAgentVersion
from app.ai.agents.runtime import AgentDeps
from app.ai.agents.spec import AgentSpec
from app.ai.evaluation import scoring
from app.ai.evaluation.models import EvalCase, EvalRun
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.rls import init_context, set_context
from app.core.tasks import CeleryTaskQueue
from app.vault.service import Vault

log = get_logger(__name__)
Clock = Callable[[], datetime]


async def _session(
    sessions: async_sessionmaker[AsyncSession], workspace_id: uuid.UUID
) -> AsyncSession:
    db = sessions()
    init_context(db)
    await set_context(db, workspace_ids=(workspace_id,))
    return db


async def _claim(db: AsyncSession, run_id: uuid.UUID, now: datetime) -> bool:
    claimed = await db.execute(
        update(EvalRun)
        .where(EvalRun.id == run_id, EvalRun.status == "queued")
        .values(status="running", started_at=now)
        .returning(EvalRun.id)
    )
    return claimed.scalar_one_or_none() is not None


async def run_evaluation(
    sessions: async_sessionmaker[AsyncSession],
    deps: AgentDeps,
    run_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> str | None:
    async with await _session(sessions, workspace_id) as db:
        if not await _claim(db, run_id, deps.clock()):
            await db.commit()
            return None
        run = await db.get(EvalRun, run_id)
        assert run is not None  # noqa: S101 - just claimed
        version = await db.get(AIAgentVersion, run.agent_version_id)
        cases = {
            c.id: c
            for c in (
                await db.execute(select(EvalCase).where(EvalCase.id.in_(run.case_ids)))
            ).scalars()
        }
        await db.commit()
        if version is None:
            return await _finish(db, run_id, "failed", deps.clock(), "agent_version_not_found")
        spec = AgentSpec.model_validate(
            {**version.spec, "engine_mode": "pinned", "engine_model_row_id": str(run.model_row_id)}
        )
        budget, ordered = run.max_cost_usd, [cases[i] for i in run.case_ids if i in cases]

    agents = WorkerAgents(sessions, deps, workspace_id)
    results: list[dict[str, object]] = []
    spent, status = Decimal(0), "succeeded"
    for case in ordered:
        if spent >= budget:
            status = "budget_exceeded"
            break
        result = await agents.run_task(
            "evaluation",
            spec,
            {"cve_id": case.cve_id, **case.input},
            str(run_id),
            context_type="evaluation",
        )
        spent += result.cost_usd
        results.append(
            scoring.score(
                str(case.id),
                case.cve_id,
                case.expected,
                run_id=str(result.run_id) if result.run_id else None,
                status=result.status,
                output=result.output,
                flags=list(result.injection_flags),
                cost_usd=result.cost_usd,
                latency_seconds=result.latency_seconds,
                error=result.error,
            ).as_dict()
        )
        async with await _session(sessions, workspace_id) as db:
            await db.execute(update(EvalRun).where(EvalRun.id == run_id).values(results=results))
            await db.commit()
    async with await _session(sessions, workspace_id) as db:
        return await _finish(db, run_id, status, deps.clock(), None, results)


async def _finish(
    db: AsyncSession,
    run_id: uuid.UUID,
    status: str,
    now: datetime,
    error: str | None,
    results: list[dict[str, object]] | None = None,
) -> str:
    values: dict[str, object] = {"status": status, "finished_at": now, "error": error}
    if results is not None:
        values["results"] = results
        values["metrics"] = scoring.metrics(results)
    await db.execute(update(EvalRun).where(EvalRun.id == run_id).values(**values))
    await db.commit()
    return status


async def evaluation_entry(settings: Settings, run_id: uuid.UUID, workspace_id: uuid.UUID) -> None:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    redis = Redis.from_url(settings.redis_url.get_secret_value())
    try:
        deps = AgentDeps(
            settings,
            Vault.from_settings(settings),
            clock=lambda: datetime.now(UTC),
            redis=redis,
            tasks=CeleryTaskQueue(),
        )
        await run_evaluation(create_sessionmaker(engine), deps, run_id, workspace_id)
    except Exception:
        log.exception("evaluation_failed")
        raise
    finally:
        await redis.aclose()
        await engine.dispose()
