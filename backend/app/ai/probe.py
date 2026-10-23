"""Ask an engine's model one question from the interface (ADR-032): the first test of a
self-hosted LLM, before any agent depends on it.

The API checks the request and queues it; only the ``ai`` worker holds the ``llm``
keyring (ADR-013), so it alone builds the connector (secrets, approved private range,
internal CA) and calls the model. The question and the answer live in Redis for a few
minutes, readable only through the same connector and scope; nothing of either is
logged or audited, only their sizes. A workspace probe goes through its budget like
any engine call. The answer is shown as plain text, never interpreted.
"""

import json
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents import budget
from app.ai.config import EngineConfig
from app.ai.connector import EngineConnectorType
from app.ai.models import AIModel
from app.ai.types import AIError, AIRequest, Message, ReasoningLevel
from app.audit.service import AuditEntry, record
from app.connectors.base import Family, get_type
from app.connectors.models import Connector
from app.connectors.quotas import QuotaExceededError
from app.connectors.runtime import HttpFactory, build_context
from app.connectors.service import get_connector
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.narrow import expect
from app.core.rate_limit import RateLimiter
from app.core.rls import init_context, set_context
from app.core.tasks import TaskQueue
from app.iam.deps import DB, WorkspaceAccess, require, require_workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.net.safe_http import EgressError
from app.vault.crypto import VaultError
from app.vault.service import Vault

log = get_logger(__name__)
PROBE_TASK = "ai.engine_probe"
PROBE_TTL_S = 15 * 60
PROBES_PER_MINUTE = 6
MAX_PROMPT = 4000
MAX_ANSWER = 8000
MAX_OUTPUT_TOKENS = 512
SYSTEM = (
    "Tu réponds à un test de connexion depuis la plateforme Vuln-Veille. "
    "Réponds brièvement, en texte simple."
)

Status = Literal["queued", "running", "succeeded", "failed"]


class ProbeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT)


class ProbeQueuedOut(BaseModel):
    probe_id: uuid.UUID


class ProbeOut(BaseModel):
    probe_id: uuid.UUID
    status: Status
    model_id: str
    answer: str | None = None
    model_served: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    duration_ms: int | None = None
    error: str | None = None


def _engine_config(connector: Connector) -> EngineConfig:
    """The connector's configuration, read by its own type (models and their state)."""
    config = get_type(connector.kind).config_model.model_validate(connector.config)
    return expect(config, EngineConfig)


def _key(probe_id: uuid.UUID) -> str:
    return f"ai_probe:{probe_id}"


async def _load(redis: Redis, probe_id: uuid.UUID) -> dict[str, Any] | None:
    raw = await redis.get(_key(probe_id))
    return cast(dict[str, Any], json.loads(raw)) if raw else None


async def _save(redis: Redis, probe_id: uuid.UUID, state: dict[str, Any]) -> None:
    await redis.set(_key(probe_id), json.dumps(state), ex=PROBE_TTL_S)


def _out(probe_id: uuid.UUID, state: dict[str, Any]) -> ProbeOut:
    return ProbeOut(
        probe_id=probe_id,
        **{k: v for k, v in state.items() if k in ProbeOut.model_fields and k != "probe_id"},
    )


async def _queue(
    request: Request,
    db: AsyncSession,
    principal: Principal,
    connector: Connector,
    body: ProbeIn,
) -> ProbeQueuedOut:
    config = _engine_config(connector)
    if not any(m.model_id == body.model_id and m.enabled for m in config.models):
        raise HTTPException(status_code=422, detail="unknown_model")
    limiter = cast(RateLimiter, request.app.state.rate_limiter)
    if not await limiter.hit("ai_probe", str(connector.id), PROBES_PER_MINUTE, 60):
        raise HTTPException(status_code=429, detail="rate_limited")
    probe_id = uuid.uuid4()
    await _save(
        request.app.state.redis,
        probe_id,
        {
            "status": "queued",
            "connector_id": str(connector.id),
            "workspace_id": str(connector.workspace_id) if connector.workspace_id else None,
            "model_id": body.model_id,
            "prompt": body.prompt,
        },
    )
    await record(
        db,
        principal.audit_ctx(request),
        AuditEntry(
            action="ai.engine_probed",
            target_type="connector",
            target_id=str(connector.id),
            workspace_id=connector.workspace_id,
            details={"model_id": body.model_id, "prompt_length": len(body.prompt)},
        ),
    )
    await db.commit()
    cast(TaskQueue, request.app.state.tasks).send(
        PROBE_TASK,
        {
            "probe_id": str(probe_id),
            "connector_id": str(connector.id),
            "workspace_id": str(connector.workspace_id) if connector.workspace_id else None,
        },
    )
    return ProbeQueuedOut(probe_id=probe_id)


async def _read(request: Request, connector: Connector, probe_id: uuid.UUID) -> ProbeOut:
    state = await _load(request.app.state.redis, probe_id)
    if state is None or state.get("connector_id") != str(connector.id):
        raise HTTPException(status_code=404, detail="not_found")
    return _out(probe_id, state)


def build_probe_router() -> APIRouter:
    router = APIRouter(tags=["ai"])
    family = Family.AI_ENGINE
    manager_dep = Annotated[
        WorkspaceAccess, Depends(require_workspace(Permission.AI_ENGINE_MANAGE))
    ]
    admin_dep = Annotated[Principal, Depends(require(Permission.CONNECTOR_GLOBAL_MANAGE))]
    workspace_base = "/workspaces/{workspace}/connectors/ai_engine/{connector_id}/probe"
    global_base = "/admin/connectors/ai_engine/{connector_id}/probe"

    @router.post(workspace_base, response_model=ProbeQueuedOut, status_code=202)
    async def probe_workspace_engine(
        connector_id: uuid.UUID, body: ProbeIn, request: Request, access: manager_dep, db: DB
    ) -> ProbeQueuedOut:
        """Queues one question to a model of the connector (ai worker)."""
        connector = await get_connector(db, connector_id, access.workspace.id, family)
        return await _queue(request, db, access.principal, connector, body)

    @router.get(workspace_base + "/{probe_id}", response_model=ProbeOut)
    async def read_workspace_probe(
        connector_id: uuid.UUID, probe_id: uuid.UUID, request: Request, access: manager_dep, db: DB
    ) -> ProbeOut:
        connector = await get_connector(db, connector_id, access.workspace.id, family)
        return await _read(request, connector, probe_id)

    @router.post(global_base, response_model=ProbeQueuedOut, status_code=202)
    async def probe_global_engine(
        connector_id: uuid.UUID, body: ProbeIn, request: Request, principal: admin_dep, db: DB
    ) -> ProbeQueuedOut:
        connector = await get_connector(db, connector_id, None, family)
        return await _queue(request, db, principal, connector, body)

    @router.get(global_base + "/{probe_id}", response_model=ProbeOut)
    async def read_global_probe(
        connector_id: uuid.UUID, probe_id: uuid.UUID, request: Request, principal: admin_dep, db: DB
    ) -> ProbeOut:
        connector = await get_connector(db, connector_id, None, family)
        return await _read(request, connector, probe_id)

    return router


# --- Worker side ------------------------------------------------------------------


class _RefusedError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _error_code(exc: Exception, kind: str) -> str:
    """A stable code to show: never the exception's message (it may quote a response)."""
    code = "internal_error"
    if isinstance(exc, (_RefusedError, AIError)):
        code = exc.code
    elif isinstance(exc, EgressError):
        code = f"egress: {exc.code}"
    elif isinstance(exc, VaultError):
        code = "secret_unavailable"
    elif isinstance(exc, QuotaExceededError):
        code = f"quota_exceeded: {exc.window}"
    elif isinstance(exc, (ValidationError, KeyError)):
        code = "invalid_configuration"
    else:
        log.exception("engine_probe_failed", kind=kind)
    return code


async def ask(
    db: AsyncSession,
    settings: Settings,
    vault: Vault,
    connector: Connector,
    model_id: str,
    prompt: str,
    redis: Redis | None = None,
    http_factory: HttpFactory | None = None,
) -> dict[str, Any]:
    """One question to one model of the connector; the outcome as stored for the UI
    (and printed by ``app.cli llm-check``). Never raises for an engine failure."""
    started = time.monotonic()
    now = datetime.now(UTC)
    try:
        if connector.workspace_id is not None and (
            (await budget.state(db, connector.workspace_id, now)).exhausted
        ):
            raise _RefusedError("budget_exhausted")
        type_, ctx = await build_context(
            db, settings, vault, connector, redis, http_factory=http_factory
        )
        if not isinstance(type_, EngineConnectorType):
            raise _RefusedError("not_an_engine")
        if ctx.quotas is not None:
            await ctx.quotas.consume()
        engine = type_.engine(ctx)
        caps = engine.capabilities(model_id)
        response = await engine.complete(
            AIRequest(
                model=model_id,
                system=SYSTEM,
                messages=(Message(role="user", text=prompt),),
                reasoning_level=ReasoningLevel.LOW,
                max_output_tokens=min(MAX_OUTPUT_TOKENS, caps.max_output_tokens),
            )
        )
    except Exception as exc:  # every failure becomes a stable code
        return {"status": "failed", "error": _error_code(exc, connector.kind)}
    if connector.workspace_id is not None:
        row = (
            await db.execute(
                select(AIModel).where(
                    AIModel.connector_id == connector.id, AIModel.model_id == model_id
                )
            )
        ).scalar_one_or_none()
        cost = budget.estimate_cost(row, response.usage) if row is not None else Decimal(0)
        await budget.charge(db, connector.workspace_id, now, cost, response.usage)
    return {
        "status": "succeeded",
        "answer": response.text[:MAX_ANSWER],
        "model_served": response.model_served[:200] or model_id,
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


async def run_probe(
    settings: Settings,
    probe_id: uuid.UUID,
    connector_id: uuid.UUID,
    workspace_id: uuid.UUID | None,
    http_factory: HttpFactory | None = None,
) -> None:
    """Celery entry point (``ai`` worker)."""
    redis = Redis.from_url(settings.redis_url.get_secret_value())
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        state = await _load(redis, probe_id)
        if state is None or state.get("status") != "queued":
            return  # expired, or already handled (at-least-once delivery)
        if state.get("connector_id") != str(connector_id):
            return
        prompt = str(state.pop("prompt", ""))
        state["status"] = "running"
        await _save(redis, probe_id, state)
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(workspace_id,) if workspace_id else ())
            connector = await db.get(Connector, connector_id)
            outcome: dict[str, Any]
            if connector is None or connector.workspace_id != workspace_id:
                outcome = {"status": "failed", "error": "not_found"}
            else:
                outcome = await ask(
                    db, settings, Vault.from_settings(settings), connector,
                    str(state["model_id"]), prompt, redis, http_factory,
                )  # fmt: skip
            await db.commit()
        # The question is not kept once answered.
        await _save(redis, probe_id, {**state, **outcome})
        log.info("engine_probe_done", status=outcome["status"], error=outcome.get("error"))
    finally:
        await redis.aclose()
        await engine.dispose()


async def llm_check(
    settings: Settings, connector_id: uuid.UUID, model_id: str | None, prompt: str
) -> dict[str, Any]:
    """``python -m app.cli llm-check``: the same question from the ``ai`` worker's
    container, through the egress proxy, for the deployment smoke test."""
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, is_platform_admin=True)
            connector = await db.get(Connector, connector_id)
            if connector is None or connector.family != Family.AI_ENGINE:
                return {"status": "failed", "error": "not_found"}
            # Its secrets and approvals are read in its own scope (RLS), like the worker.
            workspaces = (connector.workspace_id,) if connector.workspace_id else ()
            await set_context(db, is_platform_admin=False, workspace_ids=workspaces)
            config = _engine_config(connector)
            enabled = [m.model_id for m in config.models if m.enabled]
            model = model_id or (enabled[0] if enabled else "")
            if model not in enabled:
                return {"status": "failed", "error": "unknown_model"}
            outcome = await ask(
                db, settings, Vault.from_settings(settings), connector, model, prompt
            )
            await db.commit()
            return {"model_id": model, **outcome}
    finally:
        await engine.dispose()
