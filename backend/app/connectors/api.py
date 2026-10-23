"""Connector management API (spec 07 §1, §6).

The family is part of the path, so each route declares its exact permission:
- workspace connectors: ``source`` -> connector.source.manage, ``ai_engine`` ->
  ai.engine.manage, ``publish`` -> connector.publish.manage;
- global connectors (``/admin/connectors/...``): connector.global.manage.

Every write needs a recent step-up and is audited. "Test the connection" is queued to
the family's worker: only workers hold the keyrings that decrypt secrets (ADR-013).
"""

import uuid
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.connectors.base import (
    FAMILY_QUEUE,
    ConnectorType,
    Family,
    Quotas,
    Scope,
    config_schema,
    registered,
)
from app.connectors.models import Connector
from app.connectors.quotas import QuotaGuard
from app.connectors.schemas import (
    CheckQueuedOut,
    ConnectorCreate,
    ConnectorOut,
    ConnectorTypeOut,
    ConnectorUpdate,
    SecretSlotOut,
    UsageOut,
)
from app.connectors.service import (
    connector_type,
    flush_unique,
    get_connector,
    health_of,
    list_connectors,
    validate_config,
    validate_quotas,
    validate_secret_refs,
)
from app.core.rate_limit import RateLimiter
from app.core.tasks import TaskQueue
from app.iam.deps import (
    DB,
    SettingsDep,
    WorkspaceAccess,
    authenticated,
    ensure_recent_step_up,
    require,
    require_workspace,
)
from app.iam.permissions import Permission
from app.iam.principal import Principal

WORKSPACE_PERMISSION = {
    Family.SOURCE: Permission.CONNECTOR_SOURCE_MANAGE,
    Family.AI_ENGINE: Permission.AI_ENGINE_MANAGE,
    Family.PUBLISH: Permission.CONNECTOR_PUBLISH_MANAGE,
}
CHECKS_PER_MINUTE = 10


def check_task(family: Family) -> str:
    return f"{FAMILY_QUEUE[family]}.connector_check"


def connector_out(connector: Connector) -> ConnectorOut:
    return ConnectorOut(
        id=connector.id,
        family=connector.family,
        kind=connector.kind,
        name=connector.name,
        config=connector.config,
        secret_refs={k: uuid.UUID(v) for k, v in connector.secret_refs.items()},
        quotas=Quotas.model_validate(connector.quotas),
        egress_domains=list(connector.egress_domains),
        enabled=connector.enabled,
        health=health_of(connector),
        last_check_at=connector.last_check_at,
        last_success_at=connector.last_success_at,
        last_error=connector.last_error,
        consecutive_failures=connector.consecutive_failures,
        allow_private_network=connector.allow_private_network,
        private_network_cidrs=[str(c) for c in connector.private_network_cidrs],
        version=connector.version,
        created_at=connector.created_at,
        updated_at=connector.updated_at,
    )


def type_out(type_: type[ConnectorType]) -> ConnectorTypeOut:
    return ConnectorTypeOut(
        kind=type_.kind,
        family=type_.family,
        label=type_.label,
        scopes=sorted(type_.scopes),
        cost_class=type_.cost_class,
        config_schema=config_schema(type_),
        secret_slots=[
            SecretSlotOut(name=s.name, label=s.label, required=s.required)
            for s in type_.secret_slots
        ],
        egress_domains=list(type_.egress_domains),
        default_quotas=type_.default_quotas,
    )


async def _audit(
    db: AsyncSession,
    request: Request,
    principal: Principal,
    action: str,
    connector: Connector,
    **details: Any,
) -> None:
    await record(
        db,
        principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="connector",
            target_id=str(connector.id),
            workspace_id=connector.workspace_id,
            details={"kind": connector.kind, "name": connector.name, **details},
        ),
    )


class _Ops:
    """Operations shared by every family and scope (``workspace_id`` None = global)."""

    def __init__(self, family: Family, scope: Scope) -> None:
        self.family = family
        self.scope = scope

    async def create(
        self,
        request: Request,
        db: AsyncSession,
        principal: Principal,
        body: ConnectorCreate,
        workspace_id: uuid.UUID | None,
    ) -> ConnectorOut:
        type_ = connector_type(body.kind, self.family, self.scope)
        config = validate_config(type_, body.config)
        quotas = validate_quotas(type_, body.quotas)
        refs = await validate_secret_refs(db, type_, body.secret_refs, workspace_id)
        connector = Connector(
            workspace_id=workspace_id,
            family=self.family,
            kind=type_.kind,
            name=body.name,
            config=config.model_dump(mode="json"),
            secret_refs=refs,
            quotas=quotas.model_dump(mode="json", exclude_none=True),
            egress_domains=list(type_.egress_for(config)),
            enabled=body.enabled,
            created_by=principal.user_id,
            updated_by=principal.user_id,
            version=1,
            consecutive_failures=0,
        )
        db.add(connector)
        await flush_unique(db)
        await type_().on_saved(db, connector)
        await _audit(db, request, principal, "connector.created", connector)
        await db.commit()
        await db.refresh(connector)
        return connector_out(connector)

    async def update(
        self,
        request: Request,
        db: AsyncSession,
        principal: Principal,
        connector_id: uuid.UUID,
        body: ConnectorUpdate,
        workspace_id: uuid.UUID | None,
    ) -> ConnectorOut:
        connector = await get_connector(db, connector_id, workspace_id, self.family)
        if body.version != connector.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        type_ = connector_type(connector.kind, self.family, self.scope)
        changed: list[str] = []
        if body.name is not None and body.name != connector.name:
            connector.name, changed = body.name, [*changed, "name"]
        if body.config is not None:
            config = validate_config(type_, body.config)
            connector.config = config.model_dump(mode="json")
            connector.egress_domains = list(type_.egress_for(config))
            changed.append("config")
        if body.secret_refs is not None:
            connector.secret_refs = await validate_secret_refs(
                db, type_, body.secret_refs, workspace_id
            )
            changed.append("secret_refs")
        if body.quotas is not None:
            connector.quotas = validate_quotas(type_, body.quotas).model_dump(
                mode="json", exclude_none=True
            )
            changed.append("quotas")
        if body.enabled is not None and body.enabled != connector.enabled:
            connector.enabled, changed = body.enabled, [*changed, "enabled"]
        if changed:
            connector.version += 1
            connector.updated_by = principal.user_id
            await flush_unique(db)
            await type_().on_saved(db, connector)
            await _audit(db, request, principal, "connector.updated", connector, fields=changed)
            await db.commit()
            await db.refresh(connector)
        return connector_out(connector)

    async def delete(
        self,
        request: Request,
        db: AsyncSession,
        principal: Principal,
        connector_id: uuid.UUID,
        workspace_id: uuid.UUID | None,
    ) -> None:
        connector = await get_connector(db, connector_id, workspace_id, self.family)
        await _audit(db, request, principal, "connector.deleted", connector)
        await db.delete(connector)
        await db.commit()

    async def check(
        self,
        request: Request,
        db: AsyncSession,
        principal: Principal,
        connector_id: uuid.UUID,
        workspace_id: uuid.UUID | None,
    ) -> CheckQueuedOut:
        connector = await get_connector(db, connector_id, workspace_id, self.family)
        limiter = cast(RateLimiter, request.app.state.rate_limiter)
        if not await limiter.hit("connector_check", str(connector.id), CHECKS_PER_MINUTE, 60):
            raise HTTPException(status_code=429, detail="rate_limited")
        await _audit(db, request, principal, "connector.check_requested", connector)
        await db.commit()
        cast(TaskQueue, request.app.state.tasks).send(
            check_task(self.family),
            {
                "connector_id": str(connector.id),
                "workspace_id": str(workspace_id) if workspace_id else None,
            },
        )
        return CheckQueuedOut()


async def usage_of(request: Request, connector: Connector) -> UsageOut:
    quotas = Quotas.model_validate(connector.quotas)
    counts = await QuotaGuard(request.app.state.redis, connector.id, quotas).usage()
    return UsageOut(**counts, quotas=quotas)


def _workspace_routes(router: APIRouter, family: Family) -> None:
    ops = _Ops(family, Scope.WORKSPACE)
    access_dep = Annotated[
        WorkspaceAccess, Depends(require_workspace(WORKSPACE_PERMISSION[family]))
    ]
    base = f"/workspaces/{{workspace}}/connectors/{family}"

    @router.get(base, response_model=list[ConnectorOut], name=f"list_workspace_{family}")
    async def list_(access: access_dep, db: DB) -> list[ConnectorOut]:
        return [connector_out(c) for c in await list_connectors(db, access.workspace.id, family)]

    @router.post(
        base, response_model=ConnectorOut, status_code=201, name=f"create_workspace_{family}"
    )
    async def create(
        body: ConnectorCreate, request: Request, access: access_dep, db: DB, settings: SettingsDep
    ) -> ConnectorOut:
        ensure_recent_step_up(access.principal, settings)
        return await ops.create(request, db, access.principal, body, access.workspace.id)

    @router.get(
        base + "/{connector_id}", response_model=ConnectorOut, name=f"get_workspace_{family}"
    )
    async def get(connector_id: uuid.UUID, access: access_dep, db: DB) -> ConnectorOut:
        return connector_out(await get_connector(db, connector_id, access.workspace.id, family))

    @router.patch(
        base + "/{connector_id}", response_model=ConnectorOut, name=f"update_workspace_{family}"
    )
    async def update(
        connector_id: uuid.UUID,
        body: ConnectorUpdate,
        request: Request,
        access: access_dep,
        db: DB,
        settings: SettingsDep,
    ) -> ConnectorOut:
        ensure_recent_step_up(access.principal, settings)
        return await ops.update(
            request, db, access.principal, connector_id, body, access.workspace.id
        )

    @router.delete(base + "/{connector_id}", status_code=204, name=f"delete_workspace_{family}")
    async def delete(
        connector_id: uuid.UUID,
        request: Request,
        access: access_dep,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(access.principal, settings)
        await ops.delete(request, db, access.principal, connector_id, access.workspace.id)

    @router.get(
        base + "/{connector_id}/usage", response_model=UsageOut, name=f"usage_workspace_{family}"
    )
    async def usage(
        connector_id: uuid.UUID, request: Request, access: access_dep, db: DB
    ) -> UsageOut:
        connector = await get_connector(db, connector_id, access.workspace.id, family)
        return await usage_of(request, connector)

    @router.post(
        base + "/{connector_id}/check",
        response_model=CheckQueuedOut,
        status_code=202,
        name=f"check_workspace_{family}",
    )
    async def check(
        connector_id: uuid.UUID, request: Request, access: access_dep, db: DB
    ) -> CheckQueuedOut:
        return await ops.check(request, db, access.principal, connector_id, access.workspace.id)


def _global_routes(router: APIRouter, family: Family) -> None:
    ops = _Ops(family, Scope.GLOBAL)
    admin_dep = Annotated[Principal, Depends(require(Permission.CONNECTOR_GLOBAL_MANAGE))]
    base = f"/admin/connectors/{family}"

    @router.get(base, response_model=list[ConnectorOut], name=f"list_global_{family}")
    async def list_(principal: admin_dep, db: DB) -> list[ConnectorOut]:
        return [connector_out(c) for c in await list_connectors(db, None, family)]

    @router.post(base, response_model=ConnectorOut, status_code=201, name=f"create_global_{family}")
    async def create(
        body: ConnectorCreate,
        request: Request,
        principal: admin_dep,
        db: DB,
        settings: SettingsDep,
    ) -> ConnectorOut:
        ensure_recent_step_up(principal, settings)
        return await ops.create(request, db, principal, body, None)

    @router.get(base + "/{connector_id}", response_model=ConnectorOut, name=f"get_global_{family}")
    async def get(connector_id: uuid.UUID, principal: admin_dep, db: DB) -> ConnectorOut:
        return connector_out(await get_connector(db, connector_id, None, family))

    @router.patch(
        base + "/{connector_id}", response_model=ConnectorOut, name=f"update_global_{family}"
    )
    async def update(
        connector_id: uuid.UUID,
        body: ConnectorUpdate,
        request: Request,
        principal: admin_dep,
        db: DB,
        settings: SettingsDep,
    ) -> ConnectorOut:
        ensure_recent_step_up(principal, settings)
        return await ops.update(request, db, principal, connector_id, body, None)

    @router.delete(base + "/{connector_id}", status_code=204, name=f"delete_global_{family}")
    async def delete(
        connector_id: uuid.UUID,
        request: Request,
        principal: admin_dep,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(principal, settings)
        await ops.delete(request, db, principal, connector_id, None)

    @router.get(
        base + "/{connector_id}/usage", response_model=UsageOut, name=f"usage_global_{family}"
    )
    async def usage(
        connector_id: uuid.UUID, request: Request, principal: admin_dep, db: DB
    ) -> UsageOut:
        return await usage_of(request, await get_connector(db, connector_id, None, family))

    @router.post(
        base + "/{connector_id}/check",
        response_model=CheckQueuedOut,
        status_code=202,
        name=f"check_global_{family}",
    )
    async def check(
        connector_id: uuid.UUID, request: Request, principal: admin_dep, db: DB
    ) -> CheckQueuedOut:
        return await ops.check(request, db, principal, connector_id, None)


def build_connector_router() -> APIRouter:
    router = APIRouter(tags=["connectors"])

    @router.get("/connector-types", response_model=list[ConnectorTypeOut])
    async def list_connector_types(
        principal: Annotated[Principal, Depends(authenticated())],
    ) -> list[ConnectorTypeOut]:
        return [type_out(t) for t in sorted(registered().values(), key=lambda t: t.kind)]

    for family in Family:
        _workspace_routes(router, family)
        _global_routes(router, family)
    return router
