"""Runs the workflow engine in-process: tasks queued by the engine are executed in order."""

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from app.core.tasks import MemoryTaskQueue
from app.workflows.dispatch import dispatch_outbox, fire_schedules
from app.workflows.engine import (
    ADVANCE_TASK,
    MAIL_TASK,
    EngineDeps,
    Limits,
    advance_task,
    execute_node,
    start_run,
    sweep,
)
from app.workflows.models import Workflow, WorkflowVersion
from app.workflows.runner import advance_run
from app.workflows.service import activate, add_version
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Database


@dataclass
class Harness:
    deps: EngineDeps
    tasks: MemoryTaskQueue
    app_sessions: Any
    mails: list[dict[str, Any]] = field(default_factory=list)
    parked: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    # Tasks for other workers (``publish.push``…), kept for the test to run.
    others: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    @asynccontextmanager
    async def app_db(self, workspace_id: uuid.UUID) -> AsyncIterator[AsyncSession]:
        async with self.app_sessions() as db:
            init_context(db)
            await set_context(db, workspace_ids=(workspace_id,))
            yield db

    @asynccontextmanager
    async def worker_db(self) -> AsyncIterator[AsyncSession]:
        async with self.deps.sessions() as db:
            init_context(db)
            yield db

    async def workflow(
        self, workspace_id: uuid.UUID, name: str, graph: dict[str, Any], *, active: bool = True
    ) -> uuid.UUID:
        async with self.app_db(workspace_id) as db:
            workflow = Workflow(
                id=uuid.uuid4(), workspace_id=workspace_id, name=name, status="draft", version=1
            )
            db.add(workflow)
            await db.flush()
            version = await add_version(db, workflow, graph, comment="", actor=None, now=self.now)
            if active:
                await activate(db, workflow, version, self.now)
            await db.commit()
            return workflow.id

    async def manual(
        self, workspace_id: uuid.UUID, workflow_id: uuid.UUID, payload: dict[str, Any]
    ) -> uuid.UUID:
        """Starts the active version from its ``start`` manual trigger (queued, not run)."""
        async with self.app_db(workspace_id) as db:
            workflow = await db.get(Workflow, workflow_id)
            assert workflow is not None
            assert workflow.active_version_id is not None
            version = await db.get(WorkflowVersion, workflow.active_version_id)
            assert version is not None
            run_id = await start_run(
                db,
                workflow,
                version,
                trigger_node_id="start",
                trigger_type="manual",
                payload=payload,
                idempotency_key=str(uuid.uuid4()),
                now=self.now,
            )
            await db.commit()
        assert run_id is not None
        advance_task(self.tasks, run_id, workspace_id)
        return run_id

    async def dispatch(self) -> int:
        async with self.worker_db() as db:
            started = await dispatch_outbox(db, self.tasks, self.now)
        await self.drain()
        return started

    async def schedules(self) -> int:
        async with self.worker_db() as db:
            return await fire_schedules(db, self.tasks, self.now)

    async def sweep(self) -> dict[str, int]:
        async with self.worker_db() as db:
            return await sweep(db, self.tasks, self.now)

    async def drain(self, limit: int = 500, *, skip_nodes: bool = False) -> None:
        for _ in range(limit):
            if not self.tasks.sent:
                return
            name, kwargs = self.tasks.sent.pop(0)
            if name == ADVANCE_TASK:
                await advance_run(
                    self.deps, uuid.UUID(kwargs["run_id"]), uuid.UUID(kwargs["workspace_id"])
                )
            elif name.endswith(".workflow_node"):
                if skip_nodes:
                    self.parked.append((name, kwargs))
                    continue
                await execute_node(
                    self.deps, uuid.UUID(kwargs["node_run_id"]), uuid.UUID(kwargs["workspace_id"])
                )
            elif name == MAIL_TASK:
                self.mails.append(kwargs)
            else:
                self.others.append((name, kwargs))
        raise AssertionError("the engine did not settle")

    def unpark(self) -> None:
        self.tasks.sent.extend(self.parked)
        self.parked.clear()


@asynccontextmanager
async def harness(
    database: Database, redis_url: str, limits: Limits | None = None
) -> AsyncIterator[Harness]:
    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)),
        database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
        redis_url=SecretStr(redis_url),
    )
    worker = create_engine(settings.database_url_worker.get_secret_value())
    app = create_engine(settings.database_url_app.get_secret_value())
    tasks = MemoryTaskQueue()
    deps = EngineDeps(create_sessionmaker(worker), tasks, settings, limits=limits or Limits())
    try:
        yield Harness(deps, tasks, create_sessionmaker(app))
    finally:
        await worker.dispose()
        await app.dispose()
