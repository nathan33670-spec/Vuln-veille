"""Opening an engine for a resolved model, in the ``ai`` worker (llm keyring)."""

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.connector import EngineConnectorType
from app.ai.models import AIModel
from app.ai.types import AIConfigurationError, AIEngine
from app.connectors.base import get_type
from app.connectors.models import Connector
from app.connectors.runtime import build_context
from app.core.config import Settings
from app.net.safe_http import EgressError, SafeHttpClient
from app.vault.crypto import VaultError
from app.vault.service import Vault


async def open_engine(
    db: AsyncSession,
    settings: Settings,
    vault: Vault,
    model: AIModel,
    redis: Redis | None = None,
    http: SafeHttpClient | None = None,
) -> AIEngine:
    """``http``: tests only, replaces the connector's egress client."""
    connector = await db.get(Connector, model.connector_id)
    if connector is None or not connector.enabled:
        raise AIConfigurationError("engine_disabled")
    type_cls = get_type(connector.kind)
    if not issubclass(type_cls, EngineConnectorType):
        raise AIConfigurationError("not_an_engine")
    try:
        type_, ctx = await build_context(db, settings, vault, connector, redis)
    except EgressError as exc:
        raise AIConfigurationError(f"egress: {exc.code}") from None
    except VaultError:
        raise AIConfigurationError("secret_unavailable") from None
    if http is not None:
        ctx.http = http
    assert isinstance(type_, EngineConnectorType)  # noqa: S101 - checked above
    return type_.engine(ctx)
