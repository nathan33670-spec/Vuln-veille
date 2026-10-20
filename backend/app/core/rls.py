"""Per-transaction request context for PostgreSQL Row-Level Security (ADR-006).

The context lives in ``session.info["rls"]`` and is written with ``set_config(..., true)``
at the start of every transaction, so it survives intermediate commits and never leaks
to another request through the connection pool.
"""

import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session as SyncSession

_INFO_KEY = "rls"


@dataclass(frozen=True)
class RlsContext:
    user_id: uuid.UUID | None = None
    client_org_id: uuid.UUID | None = None
    is_platform_admin: bool = False
    workspace_ids: tuple[uuid.UUID, ...] = field(default_factory=tuple)
    login_email: str | None = None
    token_hash: str | None = None
    session_hash: str | None = None

    def as_settings(self) -> dict[str, str]:
        return {
            "app.user_id": str(self.user_id) if self.user_id else "",
            "app.client_org_id": str(self.client_org_id) if self.client_org_id else "",
            "app.is_platform_admin": "true" if self.is_platform_admin else "false",
            "app.workspace_ids": "{" + ",".join(str(w) for w in self.workspace_ids) + "}",
            "app.login_email": self.login_email or "",
            "app.token_hash": self.token_hash or "",
            "app.session_hash": self.session_hash or "",
        }


_SET_SQL = text(
    "SELECT set_config('app.user_id', :user_id, true), "
    "set_config('app.client_org_id', :client_org_id, true), "
    "set_config('app.is_platform_admin', :is_platform_admin, true), "
    "set_config('app.workspace_ids', :workspace_ids, true), "
    "set_config('app.login_email', :login_email, true), "
    "set_config('app.token_hash', :token_hash, true), "
    "set_config('app.session_hash', :session_hash, true)"
)


def _params(ctx: RlsContext) -> dict[str, str]:
    return {key.removeprefix("app."): value for key, value in ctx.as_settings().items()}


@event.listens_for(SyncSession, "after_begin")
def _apply_on_begin(session: SyncSession, _transaction: Any, connection: Any) -> None:
    ctx = session.info.get(_INFO_KEY)
    if isinstance(ctx, RlsContext):
        connection.execute(_SET_SQL, _params(ctx))


def get_context(session: AsyncSession) -> RlsContext:
    ctx = session.info.get(_INFO_KEY)
    return ctx if isinstance(ctx, RlsContext) else RlsContext()


async def set_context(session: AsyncSession, **changes: Any) -> RlsContext:
    """Updates the context and applies it to the current transaction, if any."""
    ctx = replace(get_context(session), **changes)
    session.info[_INFO_KEY] = ctx
    if session.in_transaction():
        await session.execute(_SET_SQL, _params(ctx))
    return ctx


def init_context(session: AsyncSession) -> None:
    session.info[_INFO_KEY] = RlsContext()
