"""Write-only secret management (SECURITY.md §4.7).

- workspace secrets: ``/workspaces/{workspace}/secrets``, permission ``secret.manage``;
- global secrets (platform connectors): ``/admin/secrets``, ``connector.global.manage``.

Every write requires a recent step-up and is audited (name and purpose, never the value).
"""

import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.connectors.service import secret_in_use
from app.iam.deps import (
    DB,
    SettingsDep,
    WorkspaceAccess,
    ensure_recent_step_up,
    require,
    require_workspace,
)
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.vault.models import Secret
from app.vault.schemas import SecretCreate, SecretOut, SecretUpdate, SecretValueIn
from app.vault.service import Vault, create_secret, get_secret, list_secrets, replace_value

WorkspaceSecrets = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.SECRET_MANAGE))]
GlobalSecrets = Annotated[Principal, Depends(require(Permission.CONNECTOR_GLOBAL_MANAGE))]


def _vault(request: Request) -> Vault:
    return cast(Vault, request.app.state.vault)


def _out(secret: Secret) -> SecretOut:
    return SecretOut(
        id=secret.id,
        name=secret.name,
        purpose=secret.purpose,
        description=secret.description,
        hint_last4=secret.hint_last4,
        value_updated_at=secret.value_updated_at,
        created_at=secret.created_at,
        version=secret.version,
    )


async def _audit(
    db: AsyncSession, request: Request, principal: Principal, action: str, secret: Secret
) -> None:
    await record(
        db,
        principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="secret",
            target_id=str(secret.id),
            workspace_id=secret.workspace_id,
            details={"name": secret.name, "purpose": secret.purpose},
        ),
    )


class _Ops:
    """The same operations for both scopes; ``workspace_id`` None means global."""

    @staticmethod
    async def create(
        request: Request,
        db: AsyncSession,
        principal: Principal,
        body: SecretCreate,
        workspace_id: uuid.UUID | None,
    ) -> SecretOut:
        secret = await create_secret(
            db,
            _vault(request),
            workspace_id=workspace_id,
            purpose=body.purpose,
            name=body.name,
            description=body.description,
            value=body.value.get_secret_value(),
            actor=principal.user_id,
        )
        await _audit(db, request, principal, "secret.created", secret)
        await db.commit()
        return _out(secret)

    @staticmethod
    async def replace(
        request: Request,
        db: AsyncSession,
        principal: Principal,
        secret_id: uuid.UUID,
        body: SecretValueIn,
        workspace_id: uuid.UUID | None,
    ) -> SecretOut:
        secret = await get_secret(db, secret_id, workspace_id)
        replace_value(_vault(request), secret, body.value.get_secret_value(), principal.user_id)
        await _audit(db, request, principal, "secret.value_replaced", secret)
        await db.commit()
        return _out(secret)

    @staticmethod
    async def update(
        request: Request,
        db: AsyncSession,
        principal: Principal,
        secret_id: uuid.UUID,
        body: SecretUpdate,
        workspace_id: uuid.UUID | None,
    ) -> SecretOut:
        secret = await get_secret(db, secret_id, workspace_id)
        secret.description = body.description
        secret.version += 1
        await _audit(db, request, principal, "secret.updated", secret)
        await db.commit()
        return _out(secret)

    @staticmethod
    async def delete(
        request: Request,
        db: AsyncSession,
        principal: Principal,
        secret_id: uuid.UUID,
        workspace_id: uuid.UUID | None,
    ) -> None:
        secret = await get_secret(db, secret_id, workspace_id)
        if await secret_in_use(db, secret.id):
            raise HTTPException(status_code=409, detail="secret_in_use")
        await _audit(db, request, principal, "secret.deleted", secret)
        await db.delete(secret)
        await db.commit()


def build_vault_router() -> APIRouter:
    router = APIRouter(tags=["secrets"])

    @router.get("/workspaces/{workspace}/secrets", response_model=list[SecretOut])
    async def list_workspace_secrets(access: WorkspaceSecrets, db: DB) -> list[SecretOut]:
        return [_out(s) for s in await list_secrets(db, access.workspace.id)]

    @router.post("/workspaces/{workspace}/secrets", response_model=SecretOut, status_code=201)
    async def create_workspace_secret(
        body: SecretCreate,
        request: Request,
        access: WorkspaceSecrets,
        db: DB,
        settings: SettingsDep,
    ) -> SecretOut:
        ensure_recent_step_up(access.principal, settings)
        return await _Ops.create(request, db, access.principal, body, access.workspace.id)

    @router.put("/workspaces/{workspace}/secrets/{secret_id}/value", response_model=SecretOut)
    async def replace_workspace_secret(
        secret_id: uuid.UUID,
        body: SecretValueIn,
        request: Request,
        access: WorkspaceSecrets,
        db: DB,
        settings: SettingsDep,
    ) -> SecretOut:
        ensure_recent_step_up(access.principal, settings)
        return await _Ops.replace(
            request, db, access.principal, secret_id, body, access.workspace.id
        )

    @router.patch("/workspaces/{workspace}/secrets/{secret_id}", response_model=SecretOut)
    async def update_workspace_secret(
        secret_id: uuid.UUID,
        body: SecretUpdate,
        request: Request,
        access: WorkspaceSecrets,
        db: DB,
    ) -> SecretOut:
        return await _Ops.update(
            request, db, access.principal, secret_id, body, access.workspace.id
        )

    @router.delete("/workspaces/{workspace}/secrets/{secret_id}", status_code=204)
    async def delete_workspace_secret(
        secret_id: uuid.UUID,
        request: Request,
        access: WorkspaceSecrets,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(access.principal, settings)
        await _Ops.delete(request, db, access.principal, secret_id, access.workspace.id)

    @router.get("/admin/secrets", response_model=list[SecretOut])
    async def list_global_secrets(principal: GlobalSecrets, db: DB) -> list[SecretOut]:
        return [_out(s) for s in await list_secrets(db, None)]

    @router.post("/admin/secrets", response_model=SecretOut, status_code=201)
    async def create_global_secret(
        body: SecretCreate,
        request: Request,
        principal: GlobalSecrets,
        db: DB,
        settings: SettingsDep,
    ) -> SecretOut:
        ensure_recent_step_up(principal, settings)
        return await _Ops.create(request, db, principal, body, None)

    @router.put("/admin/secrets/{secret_id}/value", response_model=SecretOut)
    async def replace_global_secret(
        secret_id: uuid.UUID,
        body: SecretValueIn,
        request: Request,
        principal: GlobalSecrets,
        db: DB,
        settings: SettingsDep,
    ) -> SecretOut:
        ensure_recent_step_up(principal, settings)
        return await _Ops.replace(request, db, principal, secret_id, body, None)

    @router.patch("/admin/secrets/{secret_id}", response_model=SecretOut)
    async def update_global_secret(
        secret_id: uuid.UUID,
        body: SecretUpdate,
        request: Request,
        principal: GlobalSecrets,
        db: DB,
    ) -> SecretOut:
        return await _Ops.update(request, db, principal, secret_id, body, None)

    @router.delete("/admin/secrets/{secret_id}", status_code=204)
    async def delete_global_secret(
        secret_id: uuid.UUID,
        request: Request,
        principal: GlobalSecrets,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(principal, settings)
        await _Ops.delete(request, db, principal, secret_id, None)

    return router
