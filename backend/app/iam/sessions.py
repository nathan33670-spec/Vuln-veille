"""Server-side sessions (SECURITY.md §4.2).

The cookie carries a 256-bit random token; the database only stores its SHA-256.
The CSRF token is derived from the session token with the server key, so it needs
no storage and changes whenever the session is rotated.
"""

import secrets
from datetime import UTC, datetime, timedelta
from typing import cast

from fastapi import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Audience, Settings
from app.core.crypto import keyed_hash, sha256_hex
from app.iam.models import Session, User

COOKIE_NAMES: dict[Audience, str] = {"backoffice": "__Host-vv_bo", "portal": "__Host-vv_portal"}
CSRF_HEADER = "x-csrf-token"


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    return sha256_hex(token)


def csrf_token_for(settings: Settings, session_token: str) -> str:
    return keyed_hash(settings.secret_key_bytes, session_token, "csrf")


def set_session_cookie(response: Response, audience: Audience, token: str) -> None:
    # Session cookie (no Max-Age): the server enforces idle and absolute expiry.
    response.set_cookie(
        COOKIE_NAMES[audience], token, secure=True, httponly=True, samesite="strict", path="/"
    )


def clear_session_cookie(response: Response, audience: Audience) -> None:
    response.delete_cookie(
        COOKIE_NAMES[audience], secure=True, httponly=True, samesite="strict", path="/"
    )


async def create_session(
    db: AsyncSession,
    settings: Settings,
    user: User,
    audience: Audience,
    *,
    pending: bool,
    enrollment_required: bool,
    ip: str | None,
    user_agent: str | None,
) -> tuple[str, Session]:
    token = new_session_token()
    now = utcnow()
    if pending:
        idle = absolute = now + timedelta(minutes=settings.pending_mfa_minutes)
    else:
        idle_delta, absolute_delta = settings.session_lifetimes(audience)
        idle, absolute = now + idle_delta, now + absolute_delta
    session = Session(
        id_hash=hash_session_token(token),
        user_id=user.id,
        audience=audience,
        created_at=now,
        last_seen_at=now,
        idle_expires_at=idle,
        absolute_expires_at=absolute,
        mfa_verified_at=None,
        mfa_enrollment_required=enrollment_required,
        mfa_attempts=0,
        ip=ip,
        user_agent=(user_agent or "")[:512] or None,
    )
    db.add(session)
    await db.flush()
    return token, session


async def promote_session(db: AsyncSession, settings: Settings, session: Session) -> str:
    """Marks the second factor as verified and rotates the session id (anti-fixation)."""
    now = utcnow()
    idle_delta, absolute_delta = settings.session_lifetimes(cast(Audience, session.audience))
    token = new_session_token()
    session.id_hash = hash_session_token(token)
    session.mfa_verified_at = now
    session.step_up_at = now
    session.mfa_enrollment_required = False
    session.mfa_attempts = 0
    session.last_seen_at = now
    session.idle_expires_at = now + idle_delta
    session.absolute_expires_at = now + absolute_delta
    await db.flush()
    return token


def is_expired(session: Session, now: datetime) -> bool:
    return (
        session.revoked_at is not None
        or now >= session.idle_expires_at
        or now >= session.absolute_expires_at
    )
