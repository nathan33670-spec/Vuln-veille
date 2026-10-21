"""Watch scope and followed sources of a workspace (permissions watch_scope.manage,
source.manage). Both are private to the workspace (RLS)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.catalog.models import CveRecord
from app.iam.deps import DB, WorkspaceAccess, require_workspace
from app.iam.permissions import Permission
from app.technologies.models import Technology
from app.watch.models import WatchScope, WatchSource
from app.watch.schemas import (
    ScopePreviewItem,
    ScopePreviewOut,
    WatchScopeIn,
    WatchScopeOut,
    WatchSourceCreate,
    WatchSourceOut,
    WatchSourceUpdate,
)
from app.watch.scope import match

ScopeAccess = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WATCH_SCOPE_MANAGE))]
SourceAccess = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.SOURCE_MANAGE))]
MAX_MERGE_HOPS = 5


def default_scope(workspace_id: uuid.UUID) -> WatchScope:
    return WatchScope(
        workspace_id=workspace_id,
        mode="scoped",
        technology_ids=[],
        vendors=[],
        keywords=[],
        cvss_min=None,
        include_unscored="wait",
        always_include_kev=True,
        cwe_include=[],
        cwe_exclude=[],
        version=0,
    )


async def load_scope(db: AsyncSession, workspace_id: uuid.UUID) -> WatchScope:
    return await db.get(WatchScope, workspace_id) or default_scope(workspace_id)


async def scope_technologies(db: AsyncSession, scope: WatchScope) -> list[Technology]:
    """Followed technologies, following merges to their target."""
    found: dict[uuid.UUID, Technology] = {}
    pending = list(scope.technology_ids)
    for _ in range(MAX_MERGE_HOPS):
        if not pending:
            break
        rows = await db.execute(select(Technology).where(Technology.id.in_(pending)))
        pending = []
        for tech in rows.scalars():
            if tech.status == "merged" and tech.merged_into:
                pending.append(tech.merged_into)
            else:
                found[tech.id] = tech
    return list(found.values())


def scope_out(scope: WatchScope) -> WatchScopeOut:
    return WatchScopeOut(
        mode=scope.mode,
        technology_ids=scope.technology_ids,
        vendors=scope.vendors,
        keywords=scope.keywords,
        cvss_min=scope.cvss_min,
        include_unscored=scope.include_unscored,
        always_include_kev=scope.always_include_kev,
        cwe_include=scope.cwe_include,
        cwe_exclude=scope.cwe_exclude,
        version=scope.version,
        updated_at=scope.updated_at if scope.version else None,
    )


def source_out(source: WatchSource) -> WatchSourceOut:
    return WatchSourceOut(
        id=source.id,
        name=source.name,
        type=source.type,
        config=source.config,
        tags=source.tags,
        trust_level=source.trust_level,
        enabled=source.enabled,
        version=source.version,
        updated_at=source.updated_at,
    )


async def _audit(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    action: str,
    target_type: str,
    target_id: str,
    **details: object,
) -> None:
    await record(
        db,
        access.principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type=target_type,
            target_id=target_id,
            workspace_id=access.workspace.id,
            details=details,
        ),
    )


def build_watch_router() -> APIRouter:
    router = APIRouter(prefix="/workspaces/{workspace}", tags=["watch"])

    @router.get("/watch-scope", response_model=WatchScopeOut)
    async def get_scope(access: ScopeAccess, db: DB) -> WatchScopeOut:
        return scope_out(await load_scope(db, access.workspace.id))

    @router.put("/watch-scope", response_model=WatchScopeOut)
    async def put_scope(
        body: WatchScopeIn, request: Request, access: ScopeAccess, db: DB
    ) -> WatchScopeOut:
        scope = await db.get(WatchScope, access.workspace.id, with_for_update=True)
        current = scope.version if scope else 0
        if body.version != current:
            raise HTTPException(status_code=409, detail="version_conflict")
        known = await db.execute(
            select(Technology.id).where(Technology.id.in_(body.technology_ids))
        )
        if len(set(known.scalars())) != len(set(body.technology_ids)):
            raise HTTPException(status_code=422, detail="unknown_technology")
        if scope is None:
            scope = default_scope(access.workspace.id)
            db.add(scope)
        for field, value in body.model_dump(exclude={"version"}).items():
            setattr(scope, field, value)
        scope.version = current + 1
        scope.updated_by = access.principal.user_id
        scope.updated_at = datetime.now(UTC)
        await _audit(
            db,
            request,
            access,
            "watch_scope.updated",
            "watch_scope",
            str(access.workspace.id),
            mode=body.mode,
            technologies=len(body.technology_ids),
        )
        await db.commit()
        return scope_out(scope)

    @router.get("/watch-scope/preview", response_model=ScopePreviewOut)
    async def preview_scope(
        access: ScopeAccess,
        db: DB,
        days: Annotated[int, Query(ge=1, le=90)] = 7,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> ScopePreviewOut:
        """What the current scope would have let through among recent CVEs."""
        scope = await load_scope(db, access.workspace.id)
        technologies = await scope_technologies(db, scope)
        since = datetime.now(UTC) - timedelta(days=days)
        rows = await db.execute(
            select(CveRecord)
            .where(CveRecord.published_at >= since)
            .order_by(CveRecord.published_at.desc())
            .limit(5000)
        )
        counts = {"in_scope": 0, "pending": 0, "out_of_scope": 0}
        items: list[ScopePreviewItem] = []
        total = 0
        for cve in rows.scalars():
            total += 1
            decision = match(scope, cve, technologies)
            counts[decision.decision] += 1
            if decision.decision != "out_of_scope" and len(items) < limit:
                items.append(
                    ScopePreviewItem(
                        cve_id=cve.cve_id,
                        published_at=cve.published_at,
                        severity=cve.severity,
                        base_score=cve.base_score,
                        decision=decision.decision,
                        reasons=decision.reasons,
                    )
                )
        return ScopePreviewOut(days=days, total=total, items=items, **counts)

    @router.get("/sources", response_model=list[WatchSourceOut])
    async def list_sources(access: SourceAccess, db: DB) -> list[WatchSourceOut]:
        rows = await db.execute(
            select(WatchSource)
            .where(WatchSource.workspace_id == access.workspace.id)
            .order_by(WatchSource.name)
        )
        return [source_out(s) for s in rows.scalars()]

    @router.post("/sources", response_model=WatchSourceOut, status_code=201)
    async def create_source(
        body: WatchSourceCreate, request: Request, access: SourceAccess, db: DB
    ) -> WatchSourceOut:
        source = WatchSource(
            workspace_id=access.workspace.id,
            name=body.name,
            type=body.config.type,
            config=body.config.model_dump(mode="json"),
            tags=body.tags,
            trust_level=body.trust_level,
            enabled=body.enabled,
            version=1,
            created_by=access.principal.user_id,
        )
        db.add(source)
        await _flush(db)
        await _audit(
            db,
            request,
            access,
            "source.created",
            "watch_source",
            str(source.id),
            name=source.name,
            type=source.type,
        )
        await db.commit()
        await db.refresh(source)
        return source_out(source)

    @router.patch("/sources/{source_id}", response_model=WatchSourceOut)
    async def update_source(
        source_id: uuid.UUID,
        body: WatchSourceUpdate,
        request: Request,
        access: SourceAccess,
        db: DB,
    ) -> WatchSourceOut:
        source = await _source(db, source_id, access)
        if body.version != source.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        changes = body.model_dump(exclude={"version", "config"}, exclude_none=True)
        for field, value in changes.items():
            setattr(source, field, value)
        if body.config is not None:
            source.type, source.config = body.config.type, body.config.model_dump(mode="json")
            changes["config"] = True
        if changes:
            source.version += 1
            await _flush(db)
            await _audit(
                db,
                request,
                access,
                "source.updated",
                "watch_source",
                str(source.id),
                fields=sorted(changes),
            )
            await db.commit()
            await db.refresh(source)
        return source_out(source)

    @router.delete("/sources/{source_id}", status_code=204)
    async def delete_source(
        source_id: uuid.UUID, request: Request, access: SourceAccess, db: DB
    ) -> None:
        source = await _source(db, source_id, access)
        await _audit(
            db, request, access, "source.deleted", "watch_source", str(source.id), name=source.name
        )
        await db.delete(source)
        await db.commit()

    return router


async def _source(db: AsyncSession, source_id: uuid.UUID, access: WorkspaceAccess) -> WatchSource:
    source = await db.get(WatchSource, source_id)
    if source is None or source.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return source


async def _flush(db: AsyncSession) -> None:
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="name_taken") from exc
