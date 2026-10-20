"""The authenticated caller and its effective permissions (RBAC.md)."""

import uuid
from dataclasses import dataclass, field

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditContext
from app.iam.models import (
    ClientMembership,
    ClientOrganization,
    Session,
    User,
    UserGlobalRole,
    Workspace,
    WorkspaceMembership,
)
from app.iam.permissions import (
    CLIENT_ROLES,
    MEMBERSHIP_GLOBAL,
    PLATFORM_ADMIN,
    WORKSPACE_ROLES,
    Permission,
)


@dataclass(frozen=True)
class WorkspaceGrant:
    id: uuid.UUID
    slug: str
    name: str
    role: str
    permissions: frozenset[Permission]


@dataclass(frozen=True)
class Grants:
    global_permissions: frozenset[Permission] = frozenset()
    global_roles: tuple[str, ...] = ()
    workspaces: dict[str, WorkspaceGrant] = field(default_factory=dict)
    client_org_id: uuid.UUID | None = None
    client_org_name: str | None = None
    client_role: str | None = None

    @property
    def is_platform_admin(self) -> bool:
        return Permission.IAM_USERS_MANAGE in self.global_permissions


@dataclass(frozen=True)
class Principal:
    user: User
    session: Session
    session_token: str
    pending: bool
    mfa_enabled: bool
    grants: Grants

    @property
    def user_id(self) -> uuid.UUID:
        return self.user.id

    def can(self, permission: Permission) -> bool:
        return permission in self.grants.global_permissions

    def workspace(self, slug: str, permission: Permission) -> WorkspaceGrant | None:
        grant = self.grants.workspaces.get(slug)
        return grant if grant is not None and permission in grant.permissions else None

    def audit_ctx(self, request: Request) -> AuditContext:
        return AuditContext(
            actor_user_id=self.user.id,
            actor_type="user",
            ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        )


async def load_grants(db: AsyncSession, user: User) -> Grants:
    if user.user_type == "client":
        row = (
            await db.execute(
                select(ClientMembership, ClientOrganization)
                .join(ClientOrganization, ClientOrganization.id == ClientMembership.client_org_id)
                .where(ClientMembership.user_id == user.id)
            )
        ).first()
        if row is None or row[1].status != "active":
            return Grants()
        membership, org = row
        return Grants(
            global_permissions=CLIENT_ROLES.get(membership.role, frozenset()),
            client_org_id=org.id,
            client_org_name=org.name,
            client_role=membership.role,
        )

    roles = tuple(
        (await db.execute(select(UserGlobalRole.role).where(UserGlobalRole.user_id == user.id)))
        .scalars()
        .all()
    )
    permissions: set[Permission] = set()
    if "platform_admin" in roles:
        permissions |= PLATFORM_ADMIN

    workspaces: dict[str, WorkspaceGrant] = {}
    rows = await db.execute(
        select(WorkspaceMembership.role, Workspace)
        .join(Workspace, Workspace.id == WorkspaceMembership.workspace_id)
        .where(WorkspaceMembership.user_id == user.id)
    )
    for role, workspace in rows.all():
        workspaces[workspace.slug] = WorkspaceGrant(
            id=workspace.id,
            slug=workspace.slug,
            name=workspace.name,
            role=role,
            permissions=WORKSPACE_ROLES.get(role, frozenset()),
        )
        permissions |= MEMBERSHIP_GLOBAL.get(role, frozenset())
        # Decision Q1: VOC analysts are platform administrators.
        if workspace.grants_platform_admin and role == "analyst":
            permissions |= PLATFORM_ADMIN
    return Grants(
        global_permissions=frozenset(permissions), global_roles=roles, workspaces=workspaces
    )
