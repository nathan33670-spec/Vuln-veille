"""Builds the two ASGI applications (back-office and client portal) from shared code.

Back-office routes are never mounted on the portal application (ADR-003).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from app.ai.api import build_ai_router
from app.audit.api import build_audit_router
from app.catalog.api import build_catalog_router
from app.connectors.api import build_connector_router
from app.core import health
from app.core.config import Audience, Settings, get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.errors import UnhandledErrorMiddleware, register_error_handlers
from app.core.logging import configure_logging
from app.core.mailer import Mailer, mailer_for
from app.core.middleware import (
    BodySizeLimitMiddleware,
    OriginCheckMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.rate_limit import RateLimiter
from app.core.tasks import CeleryTaskQueue, TaskQueue
from app.iam.admin_api import build_admin_router
from app.iam.auth_api import build_auth_router
from app.iam.portal_org_api import build_portal_org_router
from app.technologies.api import build_technology_router
from app.vault.api import build_vault_router
from app.vault.service import Vault
from app.vulns.api import build_vulnerability_router
from app.watch.api import build_watch_router
from app.workflows.api import build_workflow_router

API_PREFIX: dict[Audience, str] = {
    "backoffice": "/api/v1",
    "portal": "/api/portal/v1",
}


def create_app(
    audience: Audience,
    settings: Settings | None = None,
    mailer: Mailer | None = None,
    tasks: TaskQueue | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(settings.database_url_for(audience))
        redis = Redis.from_url(settings.redis_url.get_secret_value())
        app.state.engine = engine
        app.state.sessionmaker = create_sessionmaker(engine)
        app.state.redis = redis
        app.state.rate_limiter = RateLimiter(redis)
        try:
            yield
        finally:
            await redis.aclose()
            await engine.dispose()

    # Interactive docs and the OpenAPI schema are only exposed outside production.
    docs_enabled = not settings.is_prod
    prefix = API_PREFIX[audience]
    app = FastAPI(
        title=f"Vuln-Veille {audience} API",
        version="0.1.0",
        lifespan=lifespan,
        openapi_url=f"{prefix}/openapi.json" if docs_enabled else None,
        docs_url=f"{prefix}/docs" if docs_enabled else None,
        redoc_url=None,
    )
    app.state.audience = audience
    app.state.settings = settings
    app.state.mailer = mailer or mailer_for(settings)
    app.state.vault = Vault.from_settings(settings)
    app.state.tasks = tasks or CeleryTaskQueue()

    register_error_handlers(app)
    app.include_router(health.router)
    app.include_router(build_auth_router(), prefix=prefix)
    if audience == "backoffice":
        app.include_router(build_admin_router(), prefix=prefix)
        app.include_router(build_audit_router(), prefix=prefix)
        app.include_router(build_vault_router(), prefix=prefix)
        app.include_router(build_connector_router(), prefix=prefix)
        app.include_router(build_catalog_router(), prefix=prefix)
        app.include_router(build_technology_router(), prefix=prefix)
        app.include_router(build_watch_router(), prefix=prefix)
        app.include_router(build_vulnerability_router(), prefix=prefix)
        app.include_router(build_workflow_router(), prefix=prefix)
        app.include_router(build_ai_router(), prefix=prefix)
    else:
        app.include_router(build_portal_org_router(), prefix=prefix)

    # Starlette runs the last-added middleware first.
    # Order (outermost first): request id, security headers, origin check, catch-all errors,
    # body limit.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(UnhandledErrorMiddleware)
    app.add_middleware(OriginCheckMiddleware, allowed_origin=settings.origin_for(audience))
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
    return app
