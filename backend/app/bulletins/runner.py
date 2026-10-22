"""Draft requests in the ``ai`` worker (``ai.bulletin_draft``, spec 04 §3).

A request is claimed once (``queued`` → ``running``), its progress recorded step by step
for the interface (server-sent events), then ``succeeded`` with its bulletin, or
``failed`` with a stable error code. Three kinds: a new draft, one field regenerated on
an existing bulletin, a translation linked to its source.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.agents.invoke import AgentResult, WorkerAgents
from app.ai.agents.runtime import AgentDeps
from app.ai.agents.spec import AgentSpec
from app.bulletins.facts import vulnerability_facts
from app.bulletins.fields import clean_fields
from app.bulletins.generation import (
    DraftInput,
    GenerationError,
    TaskRunner,
    add_revision,
    build_payload,
    create_draft,
    generate_ai_fields,
)
from app.bulletins.lifecycle import after_edit
from app.bulletins.models import (
    Bulletin,
    BulletinRevision,
    BulletinTemplateVersion,
    BulletinVulnerability,
    DraftRequest,
)
from app.bulletins.spec import parse_spec
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.rls import init_context, set_context
from app.core.tasks import CeleryTaskQueue
from app.vault.service import Vault

log = get_logger(__name__)
DRAFT_TASK = "ai.bulletin_draft"


async def _session(
    sessions: async_sessionmaker[AsyncSession], workspace_id: uuid.UUID
) -> AsyncSession:
    db = sessions()
    init_context(db)
    await set_context(db, workspace_ids=(workspace_id,))
    return db


async def _step(
    sessions: async_sessionmaker[AsyncSession],
    request_id: uuid.UUID,
    workspace_id: uuid.UUID,
    step: str,
    now: datetime,
    **values: Any,
) -> None:
    async with await _session(sessions, workspace_id) as db:
        request = await db.get(DraftRequest, request_id)
        if request is not None:
            request.progress = [*request.progress, {"step": step, "at": now.isoformat()}]
            for key, value in values.items():
                setattr(request, key, value)
            await db.commit()


def _runner(agents: WorkerAgents) -> TaskRunner:
    async def run(task: str, spec: AgentSpec, payload: dict[str, Any], context: str) -> AgentResult:
        return await agents.run_task(task, spec, payload, context, context_type="draft_request")

    return run


async def run_draft_request(
    sessions: async_sessionmaker[AsyncSession],
    deps: AgentDeps,
    request_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> str | None:
    clock: Callable[[], datetime] = deps.clock
    async with await _session(sessions, workspace_id) as db:
        claimed = await db.execute(
            update(DraftRequest)
            .where(DraftRequest.id == request_id, DraftRequest.status == "queued")
            .values(status="running", started_at=clock(), progress=[])
            .returning(DraftRequest.id)
        )
        await db.commit()
        if claimed.scalar_one_or_none() is None:
            return None  # already handled (at-least-once delivery)
    await _step(sessions, request_id, workspace_id, "context", clock())
    run_task = _runner(WorkerAgents(sessions, deps, workspace_id))
    try:
        async with await _session(sessions, workspace_id) as db:
            request = await db.get(DraftRequest, request_id)
            assert request is not None  # noqa: S101 - claimed above
            bulletin = await _execute(db, request, run_task, clock())
            await db.commit()
            bulletin_id = bulletin.id
    except GenerationError as exc:
        await _step(
            sessions, request_id, workspace_id, "failed", clock(),
            status="failed", error=str(exc)[:200], finished_at=clock(),
        )  # fmt: skip
        return "failed"
    except Exception:
        log.exception("draft_request_failed", request_id=str(request_id))
        await _step(
            sessions, request_id, workspace_id, "failed", clock(),
            status="failed", error="internal_error", finished_at=clock(),
        )  # fmt: skip
        return "failed"
    await _step(
        sessions, request_id, workspace_id, "done", clock(),
        status="succeeded", bulletin_id=bulletin_id, finished_at=clock(),
    )  # fmt: skip
    return "succeeded"


async def _execute(
    db: AsyncSession, request: DraftRequest, run_task: TaskRunner, now: datetime
) -> Bulletin:
    data = request.input
    context = str(request.id)
    if request.kind == "draft":
        version = await db.get(BulletinTemplateVersion, request.template_version_id)
        if version is None:
            raise GenerationError("template_not_found")
        bulletin, generated = await create_draft(
            db,
            run_task,
            DraftInput(
                workspace_id=request.workspace_id,
                version=version,
                vulnerability_ids=[uuid.UUID(v) for v in data.get("vulnerability_ids", [])],
                text=str(data.get("text") or ""),
                urls=[str(u) for u in data.get("urls") or []],
                extra_instructions=request.extra_instructions,
                author=request.requested_by,
            ),
            context,
            now,
        )
        request.agent_run_id = generated.agent_run_id
        return bulletin
    source = await db.get(Bulletin, uuid.UUID(str(data.get("bulletin_id"))))
    if source is None or source.workspace_id != request.workspace_id:
        raise GenerationError("bulletin_not_found")
    revision = await db.get(BulletinRevision, source.current_revision_id)
    if revision is None:
        raise GenerationError("bulletin_not_found")
    if request.kind == "translation":
        version = await db.get(BulletinTemplateVersion, request.template_version_id)
        if version is None:
            raise GenerationError("template_not_found")
        vulns = await _vulnerabilities(db, source.id)
        bulletin, generated = await create_draft(
            db,
            run_task,
            DraftInput(
                workspace_id=request.workspace_id,
                version=version,
                vulnerability_ids=vulns,
                extra_instructions=request.extra_instructions,
                author=request.requested_by,
                translation_of=source,
                source_fields=revision.fields,
            ),
            context,
            now,
        )
        request.agent_run_id = generated.agent_run_id
        return bulletin
    # One field regenerated with the analyst's instruction: a new revision.
    if source.status == "withdrawn":
        raise GenerationError("bulletin_withdrawn")
    version = await db.get(BulletinTemplateVersion, source.template_version_id)
    assert version is not None  # noqa: S101 - foreign key
    spec = parse_spec(version.spec)
    key = str(data.get("field"))
    target = spec.field(key)
    if target is None or target.generation.mode != "ai":
        raise GenerationError("field_not_generated")
    facts = [
        f
        for f in [
            await vulnerability_facts(db, source.workspace_id, v)
            for v in await _vulnerabilities(db, source.id)
        ]
        if f is not None
    ]
    payload = await build_payload(db, source.workspace_id, facts, source_fields=revision.fields)
    generated = await generate_ai_fields(
        run_task, spec, payload, context, extra_instructions=request.extra_instructions, only=key
    )
    fields, errors = clean_fields(spec, {**revision.fields, key: generated.fields.get(key)})
    if any(e["path"] == f"fields.{key}" and e["code"] != "missing" for e in errors):
        raise GenerationError("invalid_output")
    await add_revision(
        db, source, spec, fields, by_type="ai", by=None, agent_run_id=generated.agent_run_id,
        note=f"Champ « {target.label or key} » régénéré", now=now,
    )  # fmt: skip
    after_edit(source)
    request.agent_run_id = generated.agent_run_id
    return source


async def _vulnerabilities(db: AsyncSession, bulletin_id: uuid.UUID) -> list[uuid.UUID]:
    rows = await db.execute(
        select(BulletinVulnerability.vulnerability_id).where(
            BulletinVulnerability.bulletin_id == bulletin_id
        )
    )
    return list(rows.scalars())


async def draft_entry(settings: Settings, request_id: uuid.UUID, workspace_id: uuid.UUID) -> None:
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
        await run_draft_request(create_sessionmaker(engine), deps, request_id, workspace_id)
    finally:
        await redis.aclose()
        await engine.dispose()
