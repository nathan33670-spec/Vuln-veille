"""Schemas of the administration and organization-management APIs."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from app.iam.schemas import StrictIn

DisplayName = Field(min_length=1, max_length=120)
WorkspaceRole = Literal["analyst", "viewer"]
ClientRole = Literal["client_user", "client_admin"]
UserStatus = Literal["active", "disabled"]


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    user_type: str
    status: str
    mfa_enabled: bool
    locked: bool
    last_login_at: datetime | None
    created_at: datetime


class UserWorkspaceOut(BaseModel):
    slug: str
    name: str
    role: str


class UserClientOut(BaseModel):
    id: uuid.UUID
    name: str
    role: str


class UserDetailOut(UserOut):
    global_roles: list[str]
    workspaces: list[UserWorkspaceOut]
    client_org: UserClientOut | None


class UserPage(BaseModel):
    items: list[UserOut]
    next_cursor: str | None


class InternalUserCreate(StrictIn):
    email: EmailStr = Field(max_length=254)
    display_name: str = DisplayName


class ClientUserCreate(StrictIn):
    email: EmailStr = Field(max_length=254)
    display_name: str = DisplayName
    role: ClientRole = "client_user"


OptionalDisplayName = Field(default=None, min_length=1, max_length=120)


class UserUpdate(StrictIn):
    display_name: str | None = OptionalDisplayName
    status: UserStatus | None = None


class OrgUserUpdate(StrictIn):
    display_name: str | None = OptionalDisplayName
    status: UserStatus | None = None
    role: ClientRole | None = None


class WorkspaceMembershipIn(StrictIn):
    role: WorkspaceRole


class WorkspaceAdminOut(BaseModel):
    slug: str
    name: str
    grants_platform_admin: bool
    member_count: int


class WorkspaceUpdate(StrictIn):
    name: str = Field(min_length=1, max_length=80)


class ClientOrgCreate(StrictIn):
    name: str = Field(min_length=1, max_length=120)
    mfa_required: bool = False


class ClientOrgUpdate(StrictIn):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    status: Literal["active", "disabled"] | None = None
    mfa_required: bool | None = None


class ClientOrgOut(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    mfa_required: bool
    user_count: int
    created_at: datetime


class AuditEventOut(BaseModel):
    id: int
    occurred_at: datetime
    actor_type: str
    actor_user_id: uuid.UUID | None
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    workspace_id: uuid.UUID | None
    client_org_id: uuid.UUID | None
    ip: str | None
    request_id: str | None
    details: dict[str, object]


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_before_id: int | None


class AuditVerifyOut(BaseModel):
    intact: bool
    first_broken_id: int | None
