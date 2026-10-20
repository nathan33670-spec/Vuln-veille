"""One-time tokens (invitations, password resets) and the e-mails that carry them."""

import secrets
import uuid
from datetime import timedelta

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Audience, Settings
from app.core.crypto import keyed_hash
from app.core.mailer import Mail, Mailer
from app.iam.models import AuthToken, User
from app.iam.sessions import utcnow

_PURPOSE_TTL = {"invitation", "password_reset"}


def hash_token(settings: Settings, token: str) -> str:
    return keyed_hash(settings.secret_key_bytes, token, "auth_token")


async def issue_token(
    db: AsyncSession,
    settings: Settings,
    user: User,
    purpose: str,
    audience: Audience,
    created_by: uuid.UUID | None,
) -> str:
    """Creates a token and invalidates the user's previous unused tokens of that purpose."""
    if purpose not in _PURPOSE_TTL:
        raise ValueError(purpose)
    now = utcnow()
    await db.execute(
        update(AuthToken)
        .where(AuthToken.user_id == user.id, AuthToken.purpose == purpose)
        .where(AuthToken.used_at.is_(None))
        .values(used_at=now)
    )
    ttl = (
        timedelta(hours=settings.invitation_ttl_hours)
        if purpose == "invitation"
        else timedelta(minutes=settings.password_reset_ttl_minutes)
    )
    token = secrets.token_urlsafe(32)
    db.add(
        AuthToken(
            token_hash=hash_token(settings, token),
            user_id=user.id,
            purpose=purpose,
            audience=audience,
            expires_at=now + ttl,
            created_by=created_by,
            created_at=now,  # no RETURNING needed (see users.create_invited_user)
        )
    )
    await db.flush()
    return token


def _link(settings: Settings, audience: Audience, page: str, token: str) -> str:
    # The token travels in the fragment: never sent to servers, proxies or Referer headers.
    return f"{settings.origin_for(audience)}/{page}#token={token}"


def send_invitation(
    mailer: Mailer, settings: Settings, user: User, audience: Audience, token: str
) -> None:
    link = _link(settings, audience, "invitation", token)
    mailer.send(
        Mail(
            to=user.email,
            subject="Vuln-Veille — invitation",
            body=(
                f"Bonjour {user.display_name},\n\n"
                "Un compte Vuln-Veille a été créé pour vous. Pour choisir votre mot de passe, "
                f"ouvrez ce lien (valable {settings.invitation_ttl_hours} h) :\n\n{link}\n\n"
                "Si vous n'attendiez pas cette invitation, ignorez ce message.\n"
            ),
        )
    )


def send_password_reset(
    mailer: Mailer, settings: Settings, user: User, audience: Audience, token: str
) -> None:
    link = _link(settings, audience, "reset-password", token)
    mailer.send(
        Mail(
            to=user.email,
            subject="Vuln-Veille — réinitialisation du mot de passe",
            body=(
                f"Bonjour {user.display_name},\n\n"
                "Une réinitialisation de votre mot de passe a été demandée. Lien valable "
                f"{settings.password_reset_ttl_minutes} minutes :\n\n{link}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message : "
                "votre mot de passe reste inchangé.\n"
            ),
        )
    )
