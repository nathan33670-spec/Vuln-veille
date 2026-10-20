"""User administration shared by the back-office admin API and the portal (client admins)."""

import base64
import binascii
import uuid
from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import Select, and_, delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Audience, Settings
from app.core.mailer import Mailer
from app.iam.models import (
    ClientMembership,
    ClientOrganization,
    RecoveryCode,
    Session,
    User,
    UserGlobalRole,
    UserTotp,
    Workspace,
    WorkspaceMembership,
)
from app.iam.sessions import utcnow
from app.iam.tokens import issue_token, send_invitation

MAX_PAGE_SIZE = 100


@dataclass(frozen=True)
class UserRow:
    user: User
    mfa_enabled: bool


def encode_cursor(value: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(value.bytes).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> uuid.UUID | None:
    if not cursor:
        return None
    try:
        return uuid.UUID(bytes=base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail="invalid_cursor") from exc


def users_query() -> Select[User, datetime | None]:
    return select(User, UserTotp.confirmed_at).outerjoin(
        UserTotp, and_(UserTotp.user_id == User.id, UserTotp.confirmed_at.is_not(None))
    )


async def page_users(
    db: AsyncSession, query: Select[User, datetime | None], cursor: str | None, limit: int
) -> tuple[list[UserRow], str | None]:
    """Keyset pagination on the time-ordered UUIDv7 id, newest first."""
    after = decode_cursor(cursor)
    if after is not None:
        query = query.where(User.id < after)
    rows = (await db.execute(query.order_by(User.id.desc()).limit(limit + 1))).all()
    items = [UserRow(user=u, mfa_enabled=confirmed is not None) for u, confirmed in rows[:limit]]
    next_cursor = encode_cursor(items[-1].user.id) if len(rows) > limit and items else None
    return items, next_cursor


async def create_invited_user(
    db: AsyncSession, *, email: str, display_name: str, user_type: str
) -> User:
    now = utcnow()
    # Timestamps are set here so the INSERT needs no RETURNING: under the portal role, RLS
    # would hide the new row (not yet linked to the organization) from RETURNING.
    user = User(
        email=email.lower(),
        display_name=display_name,
        user_type=user_type,
        status="invited",
        failed_login_count=0,
        locale="fr",
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="email_unavailable") from exc
    return user


async def send_new_invitation(
    db: AsyncSession,
    settings: Settings,
    mailer: Mailer,
    user: User,
    audience: Audience,
    created_by: uuid.UUID,
) -> None:
    """Issues the token in the current transaction; the caller commits, then we mail."""
    token = await issue_token(db, settings, user, "invitation", audience, created_by)
    await db.commit()
    send_invitation(mailer, settings, user, audience, token)


async def revoke_all_sessions(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(
        update(Session)
        .where(Session.user_id == user_id, Session.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


async def reset_mfa(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(delete(UserTotp).where(UserTotp.user_id == user_id))
    await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    await revoke_all_sessions(db, user_id)


async def user_roles(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    rows = await db.execute(select(UserGlobalRole.role).where(UserGlobalRole.user_id == user_id))
    return sorted(rows.scalars().all())


async def user_workspaces(db: AsyncSession, user_id: uuid.UUID) -> list[tuple[str, str, str]]:
    rows = await db.execute(
        select(Workspace.slug, Workspace.name, WorkspaceMembership.role)
        .join(Workspace, Workspace.id == WorkspaceMembership.workspace_id)
        .where(WorkspaceMembership.user_id == user_id)
        .order_by(Workspace.slug)
    )
    return [(slug, name, role) for slug, name, role in rows.all()]


async def user_client_membership(
    db: AsyncSession, user_id: uuid.UUID
) -> tuple[ClientOrganization, str] | None:
    row = (
        await db.execute(
            select(ClientOrganization, ClientMembership.role)
            .join(ClientMembership, ClientMembership.client_org_id == ClientOrganization.id)
            .where(ClientMembership.user_id == user_id)
        )
    ).first()
    return (row[0], row[1]) if row else None
