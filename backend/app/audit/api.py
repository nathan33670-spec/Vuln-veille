"""Audit consultation: global (platform admins) and per workspace (analysts)."""

import json
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, select, text

from app.audit.models import AuditEvent
from app.audit.service import AuditEntry, record
from app.iam.admin_schemas import AuditEventOut, AuditPage, AuditVerifyOut
from app.iam.deps import DB, WorkspaceAccess, require, require_workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal

MAX_PAGE = 200
MAX_EXPORT = 100_000

GlobalAuditor = Annotated[Principal, Depends(require(Permission.AUDIT_READ_GLOBAL))]
WorkspaceAuditor = Annotated[
    WorkspaceAccess, Depends(require_workspace(Permission.WORKSPACE_AUDIT_READ))
]


def _out(event: AuditEvent) -> AuditEventOut:
    return AuditEventOut(
        id=event.id,
        occurred_at=event.occurred_at,
        actor_type=event.actor_type,
        actor_user_id=event.actor_user_id,
        action=event.action,
        outcome=event.outcome,
        target_type=event.target_type,
        target_id=event.target_id,
        workspace_id=event.workspace_id,
        client_org_id=event.client_org_id,
        ip=str(event.ip) if event.ip else None,
        request_id=event.request_id,
        details=event.details,
    )


def _filtered(
    action: str | None,
    actor_user_id: uuid.UUID | None,
    target_id: str | None,
    outcome: str | None,
    since: datetime | None,
    until: datetime | None,
) -> Select[AuditEvent]:
    query = select(AuditEvent)
    if action:
        query = query.where(AuditEvent.action == action)
    if actor_user_id:
        query = query.where(AuditEvent.actor_user_id == actor_user_id)
    if target_id:
        query = query.where(AuditEvent.target_id == target_id)
    if outcome:
        query = query.where(AuditEvent.outcome == outcome)
    if since:
        query = query.where(AuditEvent.occurred_at >= since)
    if until:
        query = query.where(AuditEvent.occurred_at < until)
    return query


Action = Annotated[str | None, Query(max_length=80, pattern=r"^[a-z][a-z0-9_.]*$")]
Outcome = Annotated[str | None, Query(pattern="^(success|failure|denied)$")]
TargetId = Annotated[str | None, Query(max_length=80)]
BeforeId = Annotated[int | None, Query(ge=1)]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]


async def _page(db: DB, query: Select[AuditEvent], before_id: int | None, limit: int) -> AuditPage:
    if before_id is not None:
        query = query.where(AuditEvent.id < before_id)
    rows = (await db.execute(query.order_by(AuditEvent.id.desc()).limit(limit + 1))).scalars().all()
    items = [_out(e) for e in rows[:limit]]
    return AuditPage(
        items=items, next_before_id=items[-1].id if len(rows) > limit and items else None
    )


def build_audit_router() -> APIRouter:
    router = APIRouter(tags=["audit"])

    @router.get("/admin/audit", response_model=AuditPage)
    async def list_audit(
        _: GlobalAuditor,
        db: DB,
        action: Action = None,
        actor_user_id: uuid.UUID | None = None,
        target_id: TargetId = None,
        outcome: Outcome = None,
        since: datetime | None = None,
        until: datetime | None = None,
        before_id: BeforeId = None,
        limit: Limit = 50,
    ) -> AuditPage:
        query = _filtered(action, actor_user_id, target_id, outcome, since, until)
        return await _page(db, query, before_id, limit)

    @router.get("/admin/audit/export")
    async def export_audit(
        request: Request,
        principal: GlobalAuditor,
        db: DB,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> StreamingResponse:
        """JSON Lines, oldest first, capped at 100,000 events per export."""
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(action="audit.exported", details={"since": since, "until": until}),
        )
        await db.commit()
        query = (
            _filtered(None, None, None, None, since, until)
            .order_by(AuditEvent.id)
            .limit(MAX_EXPORT)
        )

        async def lines() -> AsyncIterator[bytes]:
            result = await db.stream_scalars(query.execution_options(yield_per=500))
            async for event in result:
                yield (
                    json.dumps(_out(event).model_dump(mode="json"), sort_keys=True) + "\n"
                ).encode()

        return StreamingResponse(
            lines(),
            media_type="application/x-ndjson",
            headers={"content-disposition": 'attachment; filename="audit.jsonl"'},
        )

    @router.get("/admin/audit/verify", response_model=AuditVerifyOut)
    async def verify_audit(_: GlobalAuditor, db: DB) -> AuditVerifyOut:
        broken = (await db.execute(text("SELECT audit_verify()"))).scalar_one()
        return AuditVerifyOut(intact=broken is None, first_broken_id=broken)

    @router.get("/workspaces/{workspace}/audit", response_model=AuditPage)
    async def workspace_audit(
        access: WorkspaceAuditor,
        db: DB,
        action: Action = None,
        outcome: Outcome = None,
        before_id: BeforeId = None,
        limit: Limit = 50,
    ) -> AuditPage:
        # RLS already restricts rows to the caller's workspaces; the filter narrows to one.
        query = _filtered(action, None, None, outcome, None, None).where(
            AuditEvent.workspace_id == access.workspace.id
        )
        return await _page(db, query, before_id, limit)

    return router
