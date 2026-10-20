"""Request and response schemas of the identity API. Inputs forbid unknown fields."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


Password = Field(min_length=1, max_length=256)
OneTimeToken = Field(min_length=16, max_length=128)
Code = Field(min_length=6, max_length=32)


class LoginIn(StrictIn):
    email: EmailStr = Field(max_length=254)
    password: str = Password


class LoginOut(BaseModel):
    status: Literal["authenticated", "mfa_required", "mfa_enrollment_required"]
    csrf_token: str


class MfaCodeIn(StrictIn):
    code: str = Code


class CsrfOut(BaseModel):
    csrf_token: str


class EnrollmentOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_data_uri: str


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
    csrf_token: str


class WorkspaceOut(BaseModel):
    slug: str
    name: str
    role: str
    permissions: list[str]


class ClientOrgOut(BaseModel):
    id: uuid.UUID
    name: str
    role: str


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    user_type: str
    locale: str
    mfa_enabled: bool
    pending_mfa: bool
    permissions: list[str]
    workspaces: list[WorkspaceOut]
    client_org: ClientOrgOut | None
    csrf_token: str


class TokenPasswordIn(StrictIn):
    token: str = OneTimeToken
    password: str = Password


class ForgotPasswordIn(StrictIn):
    email: EmailStr = Field(max_length=254)


class StepUpIn(StrictIn):
    code: str | None = Field(default=None, min_length=6, max_length=32)
    password: str | None = Field(default=None, min_length=1, max_length=256)


class PasswordChangeIn(StrictIn):
    current_password: str = Password
    new_password: str = Password


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    ip: str | None
    user_agent: str | None
    current: bool
