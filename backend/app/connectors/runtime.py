"""Connector runtime, in the workers: decrypt secrets, build the egress policy, run.

Only the worker of a family holds the keyring able to decrypt its secrets (ADR-013).
A connector reaches only the domains its type declares for its configuration, and a
private range only once an administrator approved it.
"""

import contextlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import (
    FAMILY_PURPOSE,
    ConnectorContext,
    ConnectorType,
    Family,
    HealthResult,
    Quotas,
    get_type,
)
from app.connectors.models import Connector
from app.connectors.quotas import QuotaExceededError, QuotaGuard
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.rls import init_context, set_context
from app.net.safe_http import EgressDeniedError, EgressError, EgressPolicy, egress_client
from app.net.safe_http import private_networks as parse_networks
from app.vault.crypto import VaultError
from app.vault.service import Vault, resolve_secret

log = get_logger(__name__)
MAX_ERROR_LENGTH = 500


async def build_context(
    db: AsyncSession,
    settings: Settings,
    vault: Vault,
    connector: Connector,
    redis: Redis | None = None,
) -> tuple[ConnectorType, ConnectorContext]:
    type_ = get_type(connector.kind)
    config = type_.config_model.model_validate(connector.config)
    domains = type_.egress_for(config)
    if not domains:
        raise EgressDeniedError("no_declared_domains")
    approved = connector.allow_private_network and connector.private_network_approved_by
    policy = EgressPolicy(
        allowed_domains=domains,
        private_networks=parse_networks(connector.private_network_cidrs) if approved else (),
        allowed_content_types=type_.content_types,
        max_bytes=type_.max_response_bytes,
    )
    if type_.read_timeout is not None:
        policy = replace(policy, read_timeout=type_.read_timeout)
    if type_.total_timeout is not None:
        policy = replace(policy, total_timeout=type_.total_timeout)
    purpose = FAMILY_PURPOSE[Family(connector.family)]
    secrets = {
        slot: await resolve_secret(
            db, vault, uuid.UUID(secret_id), purpose=purpose, workspace_id=connector.workspace_id
        )
        for slot, secret_id in connector.secret_refs.items()
    }
    quotas = (
        QuotaGuard(redis, connector.id, Quotas.model_validate(connector.quotas))
        if redis is not None
        else None
    )
    context = ConnectorContext(
        connector_id=connector.id,
        workspace_id=connector.workspace_id,
        config=config,
        secrets=secrets,
        http=egress_client(settings, policy),
        quotas=quotas,
    )
    return type_(), context


def record_health(connector: Connector, result: HealthResult, now: datetime) -> None:
    connector.last_check_at = now
    if result.ok:
        connector.last_success_at = now
        connector.last_error = None
        connector.consecutive_failures = 0
    else:
        connector.last_error = (result.message or "failed")[:MAX_ERROR_LENGTH]
        connector.consecutive_failures += 1


async def run_check(
    db: AsyncSession,
    settings: Settings,
    vault: Vault,
    connector: Connector,
    redis: Redis | None = None,
) -> HealthResult:
    try:
        type_, context = await build_context(db, settings, vault, connector, redis)
        if context.quotas is not None:
            await context.quotas.consume()
        result = await type_.health_check(context)
    except EgressError as exc:
        result = HealthResult(ok=False, message=f"egress: {exc.code}")
    except VaultError:
        result = HealthResult(ok=False, message="secret_unavailable")
    except QuotaExceededError as exc:
        result = HealthResult(ok=False, message=f"quota_exceeded: {exc.window}")
    except (ValidationError, KeyError):
        result = HealthResult(ok=False, message="invalid_configuration")
    except Exception:
        # Type code failed: log the type only (exception messages may quote responses).
        log.exception("connector_check_failed", kind=connector.kind)
        result = HealthResult(ok=False, message="internal_error")
    record_health(connector, result, datetime.now(UTC))
    return result


async def check_connector(
    settings: Settings, connector_id: uuid.UUID, workspace_id: uuid.UUID | None
) -> HealthResult | None:
    """Celery entry point: one connection test, result stored on the connector."""
    engine = create_engine(settings.database_url_worker.get_secret_value())
    redis = Redis.from_url(settings.redis_url.get_secret_value())
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(workspace_id,) if workspace_id else ())
            connector = await db.get(Connector, connector_id)
            if connector is None or connector.workspace_id != workspace_id:
                return None  # deleted meanwhile, or not in this task's scope
            result = await run_check(db, settings, Vault.from_settings(settings), connector, redis)
            with contextlib.suppress(KeyError):  # type no longer registered
                type_ = get_type(connector.kind)()
                await type_.on_checked(db, connector, result, datetime.now(UTC))
            await db.commit()
            return result
    finally:
        await redis.aclose()
        await engine.dispose()
