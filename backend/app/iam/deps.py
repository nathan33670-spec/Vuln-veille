"""FastAPI dependencies enforcing authentication, CSRF and permissions.

Each factory tags the dependency it returns with an access policy, which the route
test (tests/security/test_route_permissions.py) requires on every route.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access import POLICY_ATTR
from app.core.config import Audience, Settings
from app.core.crypto import constant_time_equals
from app.core.rls import init_context, set_context
from app.iam.models import Session, User, UserTotp
from app.iam.permissions import Permission
from app.iam.principal import Principal, WorkspaceGrant, load_grants
from app.iam.sessions import (
    COOKIE_NAMES,
    CSRF_HEADER,
    csrf_token_for,
    hash_session_token,
    is_expired,
    utcnow,
)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_TOUCH_INTERVAL = timedelta(seconds=60)


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    sessionmaker: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with sessionmaker() as session:
        init_context(session)
        yield session


DB = Annotated[AsyncSession, Depends(get_db)]


def get_settings_dep(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def audience_of(request: Request) -> Audience:
    return cast(Audience, request.app.state.audience)


def _unauthorized(code: str = "not_authenticated") -> HTTPException:
    return HTTPException(status_code=401, detail=code)


async def _load_principal(request: Request, db: AsyncSession, *, allow_pending: bool) -> Principal:
    settings = get_settings_dep(request)
    audience = audience_of(request)
    token = request.cookies.get(COOKIE_NAMES[audience])
    if not token or len(token) > 128:  # noqa: PLR2004
        raise _unauthorized()

    session_hash = hash_session_token(token)
    await set_context(db, session_hash=session_hash)
    session = await db.get(Session, session_hash)
    now = utcnow()
    if session is None or session.audience != audience or is_expired(session, now):
        raise _unauthorized()

    await set_context(db, user_id=session.user_id)
    user = await db.get(User, session.user_id)
    if user is None or user.status != "active":
        raise _unauthorized()

    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not constant_time_equals(sent, csrf_token_for(settings, token)):
            raise HTTPException(status_code=403, detail="csrf_failed")

    totp = await db.get(UserTotp, user.id)
    mfa_enabled = totp is not None and totp.confirmed_at is not None
    pending = session.mfa_verified_at is None and (session.mfa_enrollment_required or mfa_enabled)
    if pending and not allow_pending:
        raise _unauthorized("mfa_required")

    grants = await load_grants(db, user)
    await set_context(
        db,
        client_org_id=grants.client_org_id,
        is_platform_admin=grants.is_platform_admin,
        workspace_ids=tuple(w.id for w in grants.workspaces.values()),
    )

    if not pending and now - session.last_seen_at > _TOUCH_INTERVAL:
        idle_delta, _ = settings.session_lifetimes(audience)
        session.last_seen_at = now
        session.idle_expires_at = min(now + idle_delta, session.absolute_expires_at)
        await db.commit()

    return Principal(
        user=user,
        session=session,
        session_token=token,
        pending=pending,
        mfa_enabled=mfa_enabled,
        grants=grants,
    )


def _tag[F: Callable[..., object]](policy: str, dependency: F) -> F:
    setattr(dependency, POLICY_ATTR, policy)
    return dependency


def authenticated() -> Callable[..., Awaitable[Principal]]:
    """Any fully authenticated caller (second factor satisfied)."""

    async def dependency(request: Request, db: DB) -> Principal:
        return await _load_principal(request, db, allow_pending=False)

    return _tag("authenticated", dependency)


def pending_or_authenticated() -> Callable[..., Awaitable[Principal]]:
    """Also accepts a session still waiting for its second factor (MFA endpoints)."""

    async def dependency(request: Request, db: DB) -> Principal:
        return await _load_principal(request, db, allow_pending=True)

    return _tag("pending_session", dependency)


def require(permission: Permission) -> Callable[..., Awaitable[Principal]]:
    """A global (platform) or client-organization permission."""

    async def dependency(request: Request, db: DB) -> Principal:
        principal = await _load_principal(request, db, allow_pending=False)
        if not principal.can(permission):
            raise HTTPException(status_code=403, detail="forbidden")
        return principal

    return _tag(f"permission:{permission}", dependency)


@dataclass(frozen=True)
class WorkspaceAccess:
    principal: Principal
    workspace: WorkspaceGrant


def require_workspace(permission: Permission) -> Callable[..., Awaitable[WorkspaceAccess]]:
    """A permission inside the workspace named by the ``workspace`` path parameter.
    Non-members get 404 so that workspace existence is not disclosed."""

    async def dependency(request: Request, db: DB, workspace: str) -> WorkspaceAccess:
        principal = await _load_principal(request, db, allow_pending=False)
        grant = principal.grants.workspaces.get(workspace)
        if grant is None:
            raise HTTPException(status_code=404, detail="not_found")
        if permission not in grant.permissions:
            raise HTTPException(status_code=403, detail="forbidden")
        return WorkspaceAccess(principal=principal, workspace=grant)

    return _tag(f"workspace_permission:{permission}", dependency)


def ensure_recent_step_up(principal: Principal, settings: Settings) -> None:
    """Sensitive actions need a second-factor (or password) confirmation < N minutes old."""
    step_up_at = principal.session.step_up_at
    if step_up_at is None or utcnow() - step_up_at > timedelta(minutes=settings.step_up_minutes):
        raise HTTPException(status_code=403, detail="step_up_required")


async def user_has_confirmed_totp(db: AsyncSession, user: User) -> bool:
    row = (
        await db.execute(select(UserTotp.confirmed_at).where(UserTotp.user_id == user.id))
    ).scalar_one_or_none()
    return row is not None
