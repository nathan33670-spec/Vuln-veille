"""AI engine API: model catalogue and preferred engine (spec 07 §4.1, §6).

The platform default is set by administrators (``ai.default_engine.manage``) among
global engines; a workspace overrides it (``ai.engine.manage``) with a global engine
or one of its own. Every change is audited.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.models import AIModel
from app.ai.preferences import preference, set_preference, usable
from app.ai.schemas import AIModelOut, EngineChoiceIn, EnginePreferenceOut
from app.audit.service import AuditEntry, record
from app.iam.deps import DB, WorkspaceAccess, require, require_workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal

Reader = Annotated[Principal, Depends(require(Permission.VULN_READ))]
PlatformAdmin = Annotated[Principal, Depends(require(Permission.AI_DEFAULT_ENGINE_MANAGE))]
WorkspaceAdmin = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.AI_ENGINE_MANAGE))]


def model_out(model: AIModel, workspace_id: uuid.UUID | None = None) -> AIModelOut:
    return AIModelOut(
        id=model.id,
        connector_id=model.connector_id,
        connector_kind=model.connector_kind,
        connector_name=model.connector_name,
        scope="global" if model.workspace_id is None else "workspace",
        model_id=model.model_id,
        display_name=model.display_name,
        enabled=model.enabled,
        usable=usable(model, workspace_id if workspace_id else model.workspace_id),
        declared=model.declared,
        verified=model.verified,
        verified_at=model.verified_at,
        checks=model.checks,
        data_classes=model.data_classes,
        location=model.location,
        price_input_per_mtok=model.price_input_per_mtok,
        price_output_per_mtok=model.price_output_per_mtok,
    )


async def _audit(
    db: AsyncSession,
    request: Request,
    principal: Principal,
    action: str,
    workspace_id: uuid.UUID | None,
    model: AIModel | None,
) -> None:
    await record(
        db,
        principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="ai_engine_preference",
            target_id=str(workspace_id or "platform"),
            workspace_id=workspace_id,
            details={
                "connector_id": str(model.connector_id) if model else None,
                "model_id": model.model_id if model else None,
            },
        ),
    )


async def _choice(
    db: AsyncSession, body: EngineChoiceIn, workspace_id: uuid.UUID | None
) -> AIModel:
    model = await db.get(AIModel, body.model_row_id)
    if model is None or model.workspace_id not in (None, workspace_id):
        raise HTTPException(status_code=404, detail="not_found")
    if not usable(model, workspace_id):
        raise HTTPException(status_code=422, detail="engine_unavailable")
    return model


def build_ai_router() -> APIRouter:
    router = APIRouter(tags=["ai"])

    @router.get("/ai-models", response_model=list[AIModelOut])
    async def list_models(principal: Reader, db: DB) -> list[AIModelOut]:
        """Global engines' models, and those of the caller's workspaces (RLS)."""
        rows = await db.execute(select(AIModel).order_by(AIModel.connector_name, AIModel.model_id))
        return [model_out(m) for m in rows.scalars()]

    @router.get("/admin/ai-engine", response_model=EnginePreferenceOut)
    async def get_platform(principal: PlatformAdmin, db: DB) -> EnginePreferenceOut:
        model = await preference(db, None)
        out = model_out(model) if model else None
        return EnginePreferenceOut(
            platform=out, workspace=None, effective=out, source="platform" if out else None
        )

    @router.put("/admin/ai-engine", response_model=EnginePreferenceOut)
    async def put_platform(
        body: EngineChoiceIn, request: Request, principal: PlatformAdmin, db: DB
    ) -> EnginePreferenceOut:
        model = await _choice(db, body, None)
        if model.workspace_id is not None:
            raise HTTPException(status_code=422, detail="global_engine_required")
        await set_preference(db, None, model, principal.user_id)
        await _audit(db, request, principal, "ai_engine.platform_set", None, model)
        await db.commit()
        out = model_out(model)
        return EnginePreferenceOut(platform=out, workspace=None, effective=out, source="platform")

    @router.get("/workspaces/{workspace}/ai-engine", response_model=EnginePreferenceOut)
    async def get_workspace(access: WorkspaceAdmin, db: DB) -> EnginePreferenceOut:
        return await _workspace_view(db, access.workspace.id)

    @router.put("/workspaces/{workspace}/ai-engine", response_model=EnginePreferenceOut)
    async def put_workspace(
        body: EngineChoiceIn, request: Request, access: WorkspaceAdmin, db: DB
    ) -> EnginePreferenceOut:
        workspace_id = access.workspace.id
        model = await _choice(db, body, workspace_id)
        await set_preference(db, workspace_id, model, access.principal.user_id)
        await _audit(db, request, access.principal, "ai_engine.workspace_set", workspace_id, model)
        await db.commit()
        return await _workspace_view(db, workspace_id)

    @router.delete("/workspaces/{workspace}/ai-engine", response_model=EnginePreferenceOut)
    async def inherit(request: Request, access: WorkspaceAdmin, db: DB) -> EnginePreferenceOut:
        workspace_id = access.workspace.id
        await set_preference(db, workspace_id, None, access.principal.user_id)
        await _audit(
            db, request, access.principal, "ai_engine.workspace_inherited", workspace_id, None
        )
        await db.commit()
        return await _workspace_view(db, workspace_id)

    return router


async def _workspace_view(db: AsyncSession, workspace_id: uuid.UUID) -> EnginePreferenceOut:
    platform = await preference(db, None)
    own = await preference(db, workspace_id)
    effective, source = (own, "workspace") if own else (platform, "platform" if platform else None)
    return EnginePreferenceOut(
        platform=model_out(platform, workspace_id) if platform else None,
        workspace=model_out(own, workspace_id) if own else None,
        effective=model_out(effective, workspace_id) if effective else None,
        source=source,
    )
