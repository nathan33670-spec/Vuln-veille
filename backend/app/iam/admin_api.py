"""Back-office administration: users, roles, workspaces, client organizations (``/admin``).

Role and membership changes, MFA resets and organization deactivation require a recent
step-up (RBAC.md §5). Every change is audited.
"""

import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.core.config import Audience
from app.core.mailer import Mailer
from app.iam.admin_schemas import (
    ClientOrgCreate,
    ClientOrgOut,
    ClientOrgUpdate,
    ClientUserCreate,
    InternalUserCreate,
    UserClientOut,
    UserDetailOut,
    UserOut,
    UserPage,
    UserUpdate,
    UserWorkspaceOut,
    WorkspaceAdminOut,
    WorkspaceMembershipIn,
    WorkspaceUpdate,
)
from app.iam.deps import DB, SettingsDep, ensure_recent_step_up, require
from app.iam.models import (
    ClientMembership,
    ClientOrganization,
    User,
    UserGlobalRole,
    Workspace,
    WorkspaceMembership,
)
from app.iam.permissions import GLOBAL_ROLES, Permission
from app.iam.principal import Principal
from app.iam.sessions import utcnow
from app.iam.users import (
    MAX_PAGE_SIZE,
    UserRow,
    create_invited_user,
    page_users,
    reset_mfa,
    revoke_all_sessions,
    send_new_invitation,
    user_client_membership,
    user_roles,
    user_workspaces,
    users_query,
)

UsersAdmin = Annotated[Principal, Depends(require(Permission.IAM_USERS_MANAGE))]
RolesAdmin = Annotated[Principal, Depends(require(Permission.IAM_ROLES_MANAGE))]
WorkspacesAdmin = Annotated[Principal, Depends(require(Permission.IAM_WORKSPACES_MANAGE))]
ClientsAdmin = Annotated[Principal, Depends(require(Permission.IAM_CLIENTS_MANAGE))]


def _mailer(request: Request) -> Mailer:
    return cast(Mailer, request.app.state.mailer)


def user_out(row: UserRow) -> UserOut:
    user = row.user
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        user_type=user.user_type,
        status=user.status,
        mfa_enabled=row.mfa_enabled,
        locked=user.locked_until is not None and user.locked_until > utcnow(),
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


async def _get_user(db: AsyncSession, user_id: uuid.UUID) -> UserRow:
    row = (await db.execute(users_query().where(User.id == user_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="not_found")
    return UserRow(user=row[0], mfa_enabled=row[1] is not None)


async def _detail(db: AsyncSession, row: UserRow) -> UserDetailOut:
    client = await user_client_membership(db, row.user.id)
    return UserDetailOut(
        **user_out(row).model_dump(),
        global_roles=await user_roles(db, row.user.id),
        workspaces=[
            UserWorkspaceOut(slug=s, name=n, role=r)
            for s, n, r in await user_workspaces(db, row.user.id)
        ],
        client_org=UserClientOut(id=client[0].id, name=client[0].name, role=client[1])
        if client
        else None,
    )


async def _get_org(db: AsyncSession, org_id: uuid.UUID) -> ClientOrganization:
    org = await db.get(ClientOrganization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="not_found")
    return org


async def _org_out(db: AsyncSession, org: ClientOrganization) -> ClientOrgOut:
    count = (
        await db.execute(
            select(func.count())
            .select_from(ClientMembership)
            .where(ClientMembership.client_org_id == org.id)
        )
    ).scalar_one()
    return ClientOrgOut(
        id=org.id,
        name=org.name,
        status=org.status,
        mfa_required=bool(org.settings.get("mfa_required", False)),
        user_count=int(count),
        created_at=org.created_at,
    )


def build_admin_router() -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"])

    # ----- users -----------------------------------------------------------------------

    @router.get("/users", response_model=UserPage)
    async def list_users(
        _: UsersAdmin,
        db: DB,
        user_type: Annotated[str | None, Query(pattern="^(internal|client)$")] = None,
        status: Annotated[str | None, Query(pattern="^(invited|active|disabled)$")] = None,
        q: Annotated[str | None, Query(max_length=100)] = None,
        cursor: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    ) -> UserPage:
        query = users_query()
        if user_type:
            query = query.where(User.user_type == user_type)
        if status:
            query = query.where(User.status == status)
        if q:
            pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            query = query.where(
                User.email.ilike(pattern, escape="\\")
                | User.display_name.ilike(pattern, escape="\\")
            )
        items, next_cursor = await page_users(db, query, cursor, limit)
        return UserPage(items=[user_out(r) for r in items], next_cursor=next_cursor)

    @router.post("/users", response_model=UserDetailOut, status_code=201)
    async def invite_internal_user(
        body: InternalUserCreate,
        request: Request,
        principal: UsersAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> UserDetailOut:
        user = await create_invited_user(
            db, email=body.email, display_name=body.display_name, user_type="internal"
        )
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.user_invited",
                target_type="user",
                target_id=str(user.id),
                details={"user_type": "internal"},
            ),
        )
        await send_new_invitation(
            db, settings, _mailer(request), user, "backoffice", principal.user_id
        )
        return await _detail(db, UserRow(user=user, mfa_enabled=False))

    @router.get("/users/{user_id}", response_model=UserDetailOut)
    async def get_user(user_id: uuid.UUID, _: UsersAdmin, db: DB) -> UserDetailOut:
        return await _detail(db, await _get_user(db, user_id))

    @router.patch("/users/{user_id}", response_model=UserDetailOut)
    async def update_user(
        user_id: uuid.UUID, body: UserUpdate, request: Request, principal: UsersAdmin, db: DB
    ) -> UserDetailOut:
        row = await _get_user(db, user_id)
        user = row.user
        changes: dict[str, str] = {}
        if body.display_name is not None and body.display_name != user.display_name:
            user.display_name = body.display_name
            changes["display_name"] = "changed"
        if body.status is not None and body.status != user.status:
            if user.id == principal.user_id:
                raise HTTPException(status_code=409, detail="cannot_change_own_status")
            if user.status == "invited" and body.status == "active":
                raise HTTPException(status_code=409, detail="invitation_not_accepted")
            changes["status"] = f"{user.status}->{body.status}"
            user.status = body.status
            if body.status == "disabled":
                await revoke_all_sessions(db, user.id)
        if changes:
            await record(
                db,
                principal.audit_ctx(request),
                AuditEntry(
                    action="admin.user_updated",
                    target_type="user",
                    target_id=str(user.id),
                    details=changes,
                ),
            )
            await db.commit()
        return await _detail(db, row)

    @router.post("/users/{user_id}/invitation", status_code=204)
    async def resend_invitation(
        user_id: uuid.UUID, request: Request, principal: UsersAdmin, db: DB, settings: SettingsDep
    ) -> None:
        user = (await _get_user(db, user_id)).user
        if user.status != "invited":
            raise HTTPException(status_code=409, detail="not_invited")
        audience: Audience = "portal" if user.user_type == "client" else "backoffice"
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.invitation_resent", target_type="user", target_id=str(user.id)
            ),
        )
        await send_new_invitation(db, settings, _mailer(request), user, audience, principal.user_id)

    @router.post("/users/{user_id}/mfa/reset", status_code=204)
    async def admin_reset_mfa(
        user_id: uuid.UUID, request: Request, principal: UsersAdmin, db: DB, settings: SettingsDep
    ) -> None:
        ensure_recent_step_up(principal, settings)
        user = (await _get_user(db, user_id)).user
        await reset_mfa(db, user.id)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(action="admin.mfa_reset", target_type="user", target_id=str(user.id)),
        )
        await db.commit()

    @router.delete("/users/{user_id}/sessions", status_code=204)
    async def admin_revoke_sessions(
        user_id: uuid.UUID, request: Request, principal: UsersAdmin, db: DB
    ) -> None:
        user = (await _get_user(db, user_id)).user
        await revoke_all_sessions(db, user.id)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(action="admin.sessions_revoked", target_type="user", target_id=str(user.id)),
        )
        await db.commit()

    @router.post("/users/{user_id}/unlock", status_code=204)
    async def unlock_user(
        user_id: uuid.UUID, request: Request, principal: UsersAdmin, db: DB
    ) -> None:
        user = (await _get_user(db, user_id)).user
        user.failed_login_count = 0
        user.locked_until = None
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(action="admin.user_unlocked", target_type="user", target_id=str(user.id)),
        )
        await db.commit()

    # ----- roles and memberships (step-up required) -----------------------------------

    async def _internal_target(db: AsyncSession, user_id: uuid.UUID) -> User:
        user = (await _get_user(db, user_id)).user
        if user.user_type != "internal":
            raise HTTPException(status_code=409, detail="internal_users_only")
        return user

    @router.put("/users/{user_id}/global-roles/{role}", status_code=204)
    async def grant_global_role(
        user_id: uuid.UUID,
        role: str,
        request: Request,
        principal: RolesAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        if role not in GLOBAL_ROLES:
            raise HTTPException(status_code=404, detail="not_found")
        ensure_recent_step_up(principal, settings)
        user = await _internal_target(db, user_id)
        if await db.get(UserGlobalRole, (user.id, role)) is None:
            db.add(UserGlobalRole(user_id=user.id, role=role, granted_by=principal.user_id))
            await record(
                db,
                principal.audit_ctx(request),
                AuditEntry(
                    action="admin.role_granted",
                    target_type="user",
                    target_id=str(user.id),
                    details={"role": role},
                ),
            )
            await db.commit()

    @router.delete("/users/{user_id}/global-roles/{role}", status_code=204)
    async def revoke_global_role(
        user_id: uuid.UUID,
        role: str,
        request: Request,
        principal: RolesAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(principal, settings)
        grant = await db.get(UserGlobalRole, (user_id, role))
        if grant is None:
            raise HTTPException(status_code=404, detail="not_found")
        await db.delete(grant)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.role_revoked",
                target_type="user",
                target_id=str(user_id),
                details={"role": role},
            ),
        )
        await db.commit()

    async def _workspace(db: AsyncSession, slug: str) -> Workspace:
        workspace = (
            await db.execute(select(Workspace).where(Workspace.slug == slug))
        ).scalar_one_or_none()
        if workspace is None:
            raise HTTPException(status_code=404, detail="not_found")
        return workspace

    @router.put("/users/{user_id}/workspaces/{workspace}", status_code=204)
    async def set_membership(
        user_id: uuid.UUID,
        workspace: str,
        body: WorkspaceMembershipIn,
        request: Request,
        principal: RolesAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(principal, settings)
        user = await _internal_target(db, user_id)
        target = await _workspace(db, workspace)
        membership = await db.get(WorkspaceMembership, (user.id, target.id))
        if membership is None:
            db.add(WorkspaceMembership(user_id=user.id, workspace_id=target.id, role=body.role))
        elif membership.role == body.role:
            return
        else:
            membership.role = body.role
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.membership_set",
                target_type="user",
                target_id=str(user.id),
                workspace_id=target.id,
                details={"workspace": target.slug, "role": body.role},
            ),
        )
        await db.commit()

    @router.delete("/users/{user_id}/workspaces/{workspace}", status_code=204)
    async def remove_membership(
        user_id: uuid.UUID,
        workspace: str,
        request: Request,
        principal: RolesAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        ensure_recent_step_up(principal, settings)
        target = await _workspace(db, workspace)
        membership = await db.get(WorkspaceMembership, (user_id, target.id))
        if membership is None:
            raise HTTPException(status_code=404, detail="not_found")
        await db.delete(membership)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.membership_removed",
                target_type="user",
                target_id=str(user_id),
                workspace_id=target.id,
                details={"workspace": target.slug},
            ),
        )
        await db.commit()

    # ----- workspaces ------------------------------------------------------------------

    @router.get("/workspaces", response_model=list[WorkspaceAdminOut])
    async def list_workspaces(_: WorkspacesAdmin, db: DB) -> list[WorkspaceAdminOut]:
        rows = await db.execute(
            select(Workspace, func.count(WorkspaceMembership.user_id))
            .outerjoin(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
            .group_by(Workspace.id)
            .order_by(Workspace.slug)
        )
        return [
            WorkspaceAdminOut(
                slug=w.slug,
                name=w.name,
                grants_platform_admin=w.grants_platform_admin,
                member_count=int(n),
            )
            for w, n in rows.all()
        ]

    @router.patch("/workspaces/{workspace}", response_model=WorkspaceAdminOut)
    async def update_workspace(
        workspace: str, body: WorkspaceUpdate, request: Request, principal: WorkspacesAdmin, db: DB
    ) -> WorkspaceAdminOut:
        target = await _workspace(db, workspace)
        target.name = body.name
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.workspace_updated",
                target_type="workspace",
                target_id=str(target.id),
                workspace_id=target.id,
            ),
        )
        await db.commit()
        members = (
            await db.execute(
                select(func.count())
                .select_from(WorkspaceMembership)
                .where(WorkspaceMembership.workspace_id == target.id)
            )
        ).scalar_one()
        return WorkspaceAdminOut(
            slug=target.slug,
            name=target.name,
            grants_platform_admin=target.grants_platform_admin,
            member_count=int(members),
        )

    # ----- client organizations --------------------------------------------------------

    @router.get("/clients", response_model=list[ClientOrgOut])
    async def list_clients(_: ClientsAdmin, db: DB) -> list[ClientOrgOut]:
        orgs = (
            await db.execute(select(ClientOrganization).order_by(ClientOrganization.name))
        ).scalars()
        return [await _org_out(db, org) for org in orgs.all()]

    @router.post("/clients", response_model=ClientOrgOut, status_code=201)
    async def create_client(
        body: ClientOrgCreate, request: Request, principal: ClientsAdmin, db: DB
    ) -> ClientOrgOut:
        exists = (
            await db.execute(
                select(ClientOrganization.id).where(ClientOrganization.name == body.name)
            )
        ).first()
        if exists:
            raise HTTPException(status_code=409, detail="name_taken")
        org = ClientOrganization(
            name=body.name, status="active", settings={"mfa_required": body.mfa_required}
        )
        db.add(org)
        await db.flush()
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.client_created",
                target_type="client_org",
                target_id=str(org.id),
                client_org_id=org.id,
            ),
        )
        await db.commit()
        return await _org_out(db, org)

    @router.get("/clients/{org_id}", response_model=ClientOrgOut)
    async def get_client(org_id: uuid.UUID, _: ClientsAdmin, db: DB) -> ClientOrgOut:
        return await _org_out(db, await _get_org(db, org_id))

    @router.patch("/clients/{org_id}", response_model=ClientOrgOut)
    async def update_client(
        org_id: uuid.UUID,
        body: ClientOrgUpdate,
        request: Request,
        principal: ClientsAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> ClientOrgOut:
        org = await _get_org(db, org_id)
        details: dict[str, object] = {}
        if body.name is not None and body.name != org.name:
            org.name = body.name
            details["name"] = "changed"
        if body.mfa_required is not None:
            org.settings = {**org.settings, "mfa_required": body.mfa_required}
            details["mfa_required"] = body.mfa_required
        if body.status is not None and body.status != org.status:
            ensure_recent_step_up(principal, settings)
            org.status = body.status
            details["status"] = body.status
            if body.status == "disabled":
                members = (
                    await db.execute(
                        select(ClientMembership.user_id).where(
                            ClientMembership.client_org_id == org.id
                        )
                    )
                ).scalars()
                for member_id in members.all():
                    await revoke_all_sessions(db, member_id)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.client_updated",
                target_type="client_org",
                target_id=str(org.id),
                client_org_id=org.id,
                details=details,
            ),
        )
        await db.commit()
        return await _org_out(db, org)

    @router.get("/clients/{org_id}/users", response_model=UserPage)
    async def list_client_users(
        org_id: uuid.UUID,
        _: ClientsAdmin,
        db: DB,
        cursor: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    ) -> UserPage:
        await _get_org(db, org_id)
        query = (
            users_query()
            .join(ClientMembership, ClientMembership.user_id == User.id)
            .where(ClientMembership.client_org_id == org_id)
        )
        items, next_cursor = await page_users(db, query, cursor, limit)
        return UserPage(items=[user_out(r) for r in items], next_cursor=next_cursor)

    @router.post("/clients/{org_id}/users", response_model=UserDetailOut, status_code=201)
    async def invite_client_user(
        org_id: uuid.UUID,
        body: ClientUserCreate,
        request: Request,
        principal: ClientsAdmin,
        db: DB,
        settings: SettingsDep,
    ) -> UserDetailOut:
        org = await _get_org(db, org_id)
        if org.status != "active":
            raise HTTPException(status_code=409, detail="client_disabled")
        user = await create_invited_user(
            db, email=body.email, display_name=body.display_name, user_type="client"
        )
        db.add(ClientMembership(user_id=user.id, client_org_id=org.id, role=body.role))
        await db.flush()
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="admin.user_invited",
                target_type="user",
                target_id=str(user.id),
                client_org_id=org.id,
                details={"user_type": "client", "role": body.role},
            ),
        )
        await send_new_invitation(db, settings, _mailer(request), user, "portal", principal.user_id)
        return await _detail(db, UserRow(user=user, mfa_enabled=False))

    return router
