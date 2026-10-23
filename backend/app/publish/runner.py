"""Pushes in the ``publish`` worker (``publish.push``, spec 05 §4, plan 7.3 to 7.5).

A push is claimed once per attempt (``queued`` or ``retrying`` → ``sending``), built
with the connector's decrypted secrets (this worker holds the ``connector`` keyring),
sent through the connector's egress policy, and journalled attempt by attempt with the
request redacted and an excerpt of the response stripped of any credential echoed
back. A success records the remote identifier: the next push of the bulletin to the
same connector is an update. A retryable failure (429, 5xx, network) is retried after
the configured backoff; the connector's rate limit delays a push without spending one
of its attempts. Nothing is ever sent for a bulletin that is no longer validated.
"""

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from jmespath.exceptions import JMESPathError
from redis.asyncio import Redis
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.bulletins.models import BulletinSettings
from app.connectors.base import Quotas
from app.connectors.models import Connector
from app.connectors.quotas import QuotaExceededError, QuotaGuard
from app.connectors.runtime import build_context
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.core.narrow import expect
from app.core.rls import init_context, set_context
from app.core.tasks import CeleryTaskQueue, TaskQueue
from app.iam.models import Workspace
from app.net.safe_http import EgressDeniedError, EgressError, SafeHttpClient, SafeResponse
from app.publish.config import HttpGenericConfig
from app.publish.context import (
    Publication,
    PublishError,
    load_publication,
    sample_publication,
)
from app.publish.models import PublicationTarget, PushAttempt, PushRecord
from app.publish.oauth import forget, oauth_token
from app.publish.request import PreparedRequest, build_request, redact
from app.vault.service import Vault
from app.workflows.expressions import compile_expression

log = get_logger(__name__)
PUSH_TASK = "publish.push"
EXCERPT_BYTES = 4096
RATE_DELAY_S = 60
UNAUTHORIZED = 401
OPEN = ("queued", "retrying")


@dataclass
class PushDeps:
    settings: Settings
    vault: Vault
    tasks: TaskQueue
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    redis: Redis | None = None
    http: SafeHttpClient | None = None  # tests: replaces the connector's client


@dataclass(frozen=True)
class Outcome:
    status: str  # succeeded, retrying, failed
    error: str | None = None
    response_status: int | None = None
    remote_id: str | None = None
    delay: int = 0


def push_task(record: PushRecord, countdown: int = 0) -> tuple[str, dict[str, Any], int]:
    return (
        PUSH_TASK,
        {"publication_id": str(record.id), "workspace_id": str(record.workspace_id)},
        countdown,
    )


async def _session(
    sessions: async_sessionmaker[AsyncSession], workspace_id: uuid.UUID
) -> AsyncSession:
    db = sessions()
    init_context(db)
    await set_context(db, workspace_ids=(workspace_id,))
    return db


def _excerpt(response: SafeResponse, prepared: PreparedRequest) -> str:
    text = response.content[:EXCERPT_BYTES].decode("utf-8", errors="replace")
    return redact(text, prepared.sensitive)[:EXCERPT_BYTES]


def _remote_id(config: HttpGenericConfig, response: SafeResponse) -> str | None:
    if not config.response.remote_id_path or not response.content:
        return None
    try:
        value = compile_expression(config.response.remote_id_path).search(response.json())
    except (ValueError, JMESPathError):
        return None
    if value is None or isinstance(value, dict | list | bool):
        return None
    return str(value)[:500]


def _retry(config: HttpGenericConfig, attempts: int, code: str, status: int | None) -> Outcome:
    if attempts < config.retry.max_attempts:
        backoff = config.retry.backoff_seconds
        return Outcome("retrying", code, status, delay=backoff[min(attempts, len(backoff)) - 1])
    return Outcome("failed", code, status)


async def run_push(
    sessions: async_sessionmaker[AsyncSession],
    deps: PushDeps,
    publication_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> str | None:
    async with await _session(sessions, workspace_id) as db:
        claimed = await db.execute(
            update(PushRecord)
            .where(PushRecord.id == publication_id, PushRecord.status.in_(OPEN))
            .values(status="sending", attempts=PushRecord.attempts + 1)
            .returning(PushRecord.id)
        )
        await db.commit()
        if claimed.scalar_one_or_none() is None:
            return None  # already handled (at-least-once delivery)
        record = await db.get(PushRecord, publication_id)
        assert record is not None  # noqa: S101 - claimed above
        try:
            outcome = await _attempt(db, deps, record)
        except PublishError as exc:
            outcome = Outcome("failed", exc.code[:500])
        except Exception:
            log.exception("publication_failed", publication_id=str(publication_id))
            await db.rollback()
            record = await db.get(PushRecord, publication_id)
            assert record is not None  # noqa: S101
            outcome = Outcome("failed", "internal_error")
        await _finish(db, deps, record, outcome)
        await db.commit()
        if outcome.status == "retrying":
            name, kwargs, _ = push_task(record)
            deps.tasks.send(name, kwargs, countdown=outcome.delay)
        return outcome.status


async def _publication(db: AsyncSession, record: PushRecord) -> Publication:
    if record.is_test:
        workspace = await db.get(Workspace, record.workspace_id)
        settings = await db.get(BulletinSettings, record.workspace_id)
        return sample_publication(workspace.slug if workspace else "", settings)
    assert record.bulletin_id is not None  # noqa: S101 - database check
    publication = await load_publication(db, record.workspace_id, record.bulletin_id)
    if publication.revision.id != record.revision_id:
        raise PublishError("revision_changed")  # updated since: push the new revision
    return publication


async def _attempt(db: AsyncSession, deps: PushDeps, record: PushRecord) -> Outcome:
    connector = await db.get(Connector, record.connector_id)
    if connector is None or not connector.enabled:
        raise PublishError("connector_disabled")
    publication = await _publication(db, record)
    target = None
    if record.bulletin_id is not None and not record.is_test:
        target = await db.get(PublicationTarget, (record.bulletin_id, record.connector_id))
    _, ctx = await build_context(db, deps.settings, deps.vault, connector, deps.redis)
    config = expect(ctx.config, HttpGenericConfig)
    http = deps.http or ctx.http
    record.connector_version = connector.version
    if deps.redis is not None:
        quota = Quotas(requests_per_minute=config.rate_limit_per_minute)
        try:
            await QuotaGuard(deps.redis, connector.id, quota).consume()
        except QuotaExceededError:
            record.attempts -= 1  # waiting for the rate limit spends no attempt
            return Outcome("retrying", "rate_limited", delay=RATE_DELAY_S)
    cache_key = (str(connector.id), connector.version)
    token = None
    if config.auth.type == "oauth2_client_credentials":
        token = await oauth_token(http, config, dict(ctx.secrets), cache_key=cache_key)
    prepared = build_request(
        config,
        publication,
        connector_id=str(connector.id),
        remote_id=target.remote_id if target else None,
        secrets=ctx.secrets,
        oauth_token=token,
        now=time.time(),
    )
    record.mode, record.idempotency_key = prepared.mode, prepared.idempotency_key
    return await _send(db, deps, record, config, http, prepared, target, token, cache_key)


async def _send(  # noqa: PLR0911 - one outcome per case
    db: AsyncSession,
    deps: PushDeps,
    record: PushRecord,
    config: HttpGenericConfig,
    http: SafeHttpClient,
    prepared: PreparedRequest,
    target: PublicationTarget | None,
    token: str | None,
    cache_key: tuple[str, int],
) -> Outcome:
    """One HTTP attempt, journalled; its outcome by the connector's criteria."""
    attempt = PushAttempt(
        id=uuid7(),
        workspace_id=record.workspace_id,
        publication_id=record.id,
        attempt_no=record.attempts,
        request=prepared.redacted(),
        started_at=deps.clock(),
    )
    db.add(attempt)
    started = time.monotonic()
    try:
        response = await http.request(
            prepared.method, prepared.url, headers=prepared.headers, content=prepared.body
        )
    except EgressDeniedError as exc:
        attempt.error = f"egress:{exc.code}"
        return Outcome("failed", attempt.error)
    except EgressError as exc:
        attempt.error = f"network:{exc.code}"
        if config.retry.retry_network:
            return _retry(config, record.attempts, attempt.error, None)
        return Outcome("failed", attempt.error)
    finally:
        attempt.duration_ms = int((time.monotonic() - started) * 1000)
    attempt.response_status = response.status_code
    attempt.response_excerpt = _excerpt(response, prepared)
    if response.status_code in config.response.success_status:
        remote = _remote_id(config, response) or (target.remote_id if target else None)
        return Outcome("succeeded", None, response.status_code, remote)
    code = f"http_{response.status_code}"
    attempt.error = code
    if response.status_code == UNAUTHORIZED and token is not None:
        forget(cache_key)  # an expired or revoked token: a fresh one next time
        return _retry(config, record.attempts, code, response.status_code)
    if response.status_code in config.retry.retry_on:
        return _retry(config, record.attempts, code, response.status_code)
    return Outcome("failed", code, response.status_code)


async def _finish(db: AsyncSession, deps: PushDeps, record: PushRecord, outcome: Outcome) -> None:
    now = deps.clock()
    record.status = outcome.status
    record.error = outcome.error
    record.response_status = outcome.response_status
    if outcome.status == "retrying":
        record.next_attempt_at = now + timedelta(seconds=outcome.delay)
        return
    record.finished_at, record.next_attempt_at = now, None
    if outcome.status == "succeeded":
        record.remote_id = outcome.remote_id
    if record.is_test or record.bulletin_id is None:
        return
    target = await db.get(PublicationTarget, (record.bulletin_id, record.connector_id))
    if target is None:
        target = PublicationTarget(
            workspace_id=record.workspace_id,
            bulletin_id=record.bulletin_id,
            connector_id=record.connector_id,
        )
        db.add(target)
    target.last_status, target.updated_at = outcome.status, now
    if outcome.status == "succeeded":
        target.remote_id = outcome.remote_id or target.remote_id
        target.last_rev_no = record.rev_no
        if target.first_pushed_at is None:
            target.first_pushed_at, target.first_pushed_by = now, record.requested_by


async def push_entry(
    settings: Settings, publication_id: uuid.UUID, workspace_id: uuid.UUID
) -> None:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    redis = Redis.from_url(settings.redis_url.get_secret_value())
    try:
        deps = PushDeps(settings, Vault.from_settings(settings), CeleryTaskQueue(), redis=redis)
        await run_push(create_sessionmaker(engine), deps, publication_id, workspace_id)
    finally:
        await redis.aclose()
        await engine.dispose()
