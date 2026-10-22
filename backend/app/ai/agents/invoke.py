"""Running agents and AI tasks from workflow nodes (spec 02 §7, queue ``ai``).

Each run gets its own session (same workspace RLS context): the agent runtime commits
its steps and accounting as it goes, independently of the node's transaction, so a
failed node never erases the trace of what the engine was asked and answered.
"""

import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.agents.models import AgentRun, AIAgent
from app.ai.agents.runtime import AgentDeps, execute_run
from app.ai.agents.spec import AgentSpec
from app.core.ids import uuid7
from app.core.rls import init_context, set_context


class AgentNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class AgentResult:
    status: str
    run_id: uuid.UUID | None = None
    output: dict[str, Any] | None = None
    injection_flags: tuple[dict[str, Any], ...] = ()
    cost_usd: Decimal = Decimal(0)
    error: str | None = None
    latency_seconds: float | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "succeeded"

    def as_dict(self) -> dict[str, Any]:
        """What flows to the next nodes: validated output, never raw engine text."""
        return {
            "status": self.status,
            "run_id": str(self.run_id) if self.run_id else None,
            "output": self.output,
            "injection_flags": list(self.injection_flags),
            "cost_usd": str(self.cost_usd),
            "error": self.error,
        }


@dataclass
class WorkerAgents:
    sessions: async_sessionmaker[AsyncSession]
    deps: AgentDeps
    workspace_id: uuid.UUID

    async def _session(self) -> AsyncSession:
        db = self.sessions()
        init_context(db)
        await set_context(db, workspace_ids=(self.workspace_id,))
        return db

    async def find(self, agent_id: uuid.UUID | None, preset: str | None) -> AIAgent:
        async with await self._session() as db:
            query = select(AIAgent).where(AIAgent.workspace_id == self.workspace_id)
            if agent_id is not None:
                query = query.where(AIAgent.id == agent_id)
            else:
                query = query.where(AIAgent.preset == preset)
            agent = (await db.execute(query)).scalar_one_or_none()
            if agent is None:
                raise AgentNotFoundError("agent_not_found")
            return agent

    async def run_agent(
        self,
        agent_id: uuid.UUID | None,
        preset: str | None,
        payload: dict[str, Any],
        context_id: str,
    ) -> AgentResult:
        agent = await self.find(agent_id, preset)
        if not agent.enabled:
            return AgentResult(status="skipped", error="agent_disabled")
        if agent.active_version_id is None:
            return AgentResult(status="skipped", error="no_active_version")
        return await self._run(
            payload,
            context_id,
            agent_id=agent.id,
            agent_version_id=agent.active_version_id,
        )

    async def run_task(
        self,
        task: str,
        spec: AgentSpec,
        payload: dict[str, Any],
        context_id: str,
        context_type: str = "node_run",
    ) -> AgentResult:
        return await self._run(
            payload,
            context_id,
            context_type=context_type,
            task=task,
            spec=spec.model_dump(mode="json"),
        )

    async def _run(
        self,
        payload: dict[str, Any],
        context_id: str,
        context_type: str = "node_run",
        **target: Any,
    ) -> AgentResult:
        run_id = uuid7()
        async with await self._session() as db:
            db.add(
                AgentRun(
                    id=run_id,
                    workspace_id=self.workspace_id,
                    context_type=context_type,
                    context_id=context_id,
                    input=payload,
                    status="queued",
                    queued_at=self.deps.clock(),
                    **target,
                )
            )
            await db.commit()
            await execute_run(db, self.deps, run_id)
            run = await db.get(AgentRun, run_id, populate_existing=True)
            assert run is not None  # noqa: S101 - created above
            latency = (
                (run.finished_at - run.started_at).total_seconds()
                if run.started_at and run.finished_at
                else None
            )
            return AgentResult(
                status=run.status,
                run_id=run.id,
                output=run.output,
                injection_flags=tuple(run.injection_flags),
                cost_usd=run.cost_estimate_usd,
                error=run.error,
                latency_seconds=latency,
            )
