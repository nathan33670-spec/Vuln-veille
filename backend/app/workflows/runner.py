"""Entry points of the engine tasks, with the run's workspace as RLS context."""

import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis

from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from app.core.tasks import CeleryTaskQueue
from app.vault.service import Vault
from app.workflows.engine import EngineDeps, advance, execute_node
from app.workflows.webhooks import receive


async def advance_run(deps: EngineDeps, run_id: uuid.UUID, workspace_id: uuid.UUID) -> str | None:
    async with deps.sessions() as db:
        init_context(db)
        await set_context(db, workspace_ids=(workspace_id,))
        return await advance(db, run_id, deps.tasks, deps.clock(), deps.limits)


async def advance_entry(settings: Settings, run_id: uuid.UUID, workspace_id: uuid.UUID) -> None:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        deps = EngineDeps(create_sessionmaker(engine), CeleryTaskQueue(), settings)
        await advance_run(deps, run_id, workspace_id)
    finally:
        await engine.dispose()


async def node_entry(settings: Settings, node_run_id: uuid.UUID, workspace_id: uuid.UUID) -> None:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    redis = Redis.from_url(settings.redis_url.get_secret_value())
    try:
        deps = EngineDeps(create_sessionmaker(engine), CeleryTaskQueue(), settings, redis=redis)
        await execute_node(deps, node_run_id, workspace_id)
    finally:
        await redis.aclose()
        await engine.dispose()


async def webhook_entry(
    settings: Settings, trigger_id: uuid.UUID, timestamp: str, signature: str, body: bytes
) -> str:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            return await receive(
                db,
                Vault.from_settings(settings),
                CeleryTaskQueue(),
                trigger_id=trigger_id,
                timestamp=timestamp,
                signature=signature,
                body=body,
                now=datetime.now(UTC),
            )
    finally:
        await engine.dispose()
