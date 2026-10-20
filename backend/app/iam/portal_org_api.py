"""Client referents (``client_admin``) manage the users of their own organization
(decision Q15). The portal database role and RLS confine every query to that org."""

import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.core.mailer import Mailer
from app.iam.admin_api import user_out
from app.iam.admin_schemas import ClientUserCreate, OrgUserUpdate, UserOut, UserPage
from app.iam.deps import DB, SettingsDep, require
from app.iam.models import ClientMembership, User
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.iam.users import (
    MAX_PAGE_SIZE,
    UserRow,
    create_invited_user,
    page_users,
    revoke_all_sessions,
    send_new_invitation,
    users_query,
)

OrgAdmin = Annotated[Principal, Depends(require(Permission.PORTAL_ORG_USERS_MANAGE))]


async def _org_user(db: AsyncSession, principal: Principal, user_id: uuid.UUID) -> UserRow:
    row = (
        await db.execute(
            users_query()
            .join(ClientMembership, ClientMembership.user_id == User.id)
            .where(
                User.id == user_id, ClientMembership.client_org_id == principal.grants.client_org_id
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="not_found")
    return UserRow(user=row[0], mfa_enabled=row[1] is not None)


def build_portal_org_router() -> APIRouter:
    router = APIRouter(prefix="/org", tags=["organization"])

    @router.get("/users", response_model=UserPage)
    async def list_org_users(
        principal: OrgAdmin,
        db: DB,
        cursor: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    ) -> UserPage:
        query = (
            users_query()
            .join(ClientMembership, ClientMembership.user_id == User.id)
            .where(ClientMembership.client_org_id == principal.grants.client_org_id)
        )
        items, next_cursor = await page_users(db, query, cursor, limit)
        return UserPage(items=[user_out(r) for r in items], next_cursor=next_cursor)

    @router.post("/users", response_model=UserOut, status_code=201)
    async def invite_org_user(
        body: ClientUserCreate, request: Request, principal: OrgAdmin, db: DB, settings: SettingsDep
    ) -> UserOut:
        if not await request.app.state.rate_limiter.hit(
            "org_invite", str(principal.grants.client_org_id), 30, 3600
        ):
            raise HTTPException(status_code=429, detail="rate_limited")
        org_id = principal.grants.client_org_id
        if org_id is None:  # pragma: no cover - the permission implies a membership
            raise HTTPException(status_code=403, detail="forbidden")
        user = await create_invited_user(
            db, email=body.email, display_name=body.display_name, user_type="client"
        )
        db.add(ClientMembership(user_id=user.id, client_org_id=org_id, role=body.role))
        await db.flush()
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="org.user_invited",
                target_type="user",
                target_id=str(user.id),
                client_org_id=org_id,
                details={"role": body.role},
            ),
        )
        await send_new_invitation(
            db, settings, cast(Mailer, request.app.state.mailer), user, "portal", principal.user_id
        )
        return user_out(UserRow(user=user, mfa_enabled=False))

    @router.patch("/users/{user_id}", response_model=UserOut)
    async def update_org_user(
        user_id: uuid.UUID, body: OrgUserUpdate, request: Request, principal: OrgAdmin, db: DB
    ) -> UserOut:
        row = await _org_user(db, principal, user_id)
        user = row.user
        if user.id == principal.user_id and (body.status is not None or body.role is not None):
            raise HTTPException(status_code=409, detail="cannot_change_own_access")
        details: dict[str, object] = {}
        if body.display_name is not None:
            user.display_name = body.display_name
        if body.status is not None and body.status != user.status:
            if user.status == "invited":
                raise HTTPException(status_code=409, detail="invitation_not_accepted")
            details["status"] = body.status
            user.status = body.status
            if body.status == "disabled":
                await revoke_all_sessions(db, user.id)
        if body.role is not None:
            membership = await db.get(ClientMembership, user.id)
            if membership is not None and membership.role != body.role:
                details["role"] = body.role
                membership.role = body.role
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="org.user_updated",
                target_type="user",
                target_id=str(user.id),
                client_org_id=principal.grants.client_org_id,
                details=details,
            ),
        )
        await db.commit()
        return user_out(row)

    @router.post("/users/{user_id}/invitation", status_code=204)
    async def resend_org_invitation(
        user_id: uuid.UUID, request: Request, principal: OrgAdmin, db: DB, settings: SettingsDep
    ) -> None:
        user = (await _org_user(db, principal, user_id)).user
        if user.status != "invited":
            raise HTTPException(status_code=409, detail="not_invited")
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="org.invitation_resent",
                target_type="user",
                target_id=str(user.id),
                client_org_id=principal.grants.client_org_id,
            ),
        )
        await send_new_invitation(
            db, settings, cast(Mailer, request.app.state.mailer), user, "portal", principal.user_id
        )

    return router
