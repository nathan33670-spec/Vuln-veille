"""Writes audit events through the ``audit_append`` SQL function (ADR-018)."""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

Outcome = Literal["success", "failure", "denied"]
ActorType = Literal["user", "system", "workflow", "anonymous"]

_APPEND = text(
    "SELECT audit_append(:actor_type, :actor_user_id, :action, :outcome, :target_type, "
    ":target_id, :workspace_id, :client_org_id, CAST(:ip AS inet), :request_id, "
    "CAST(:details AS jsonb))"
)


@dataclass(frozen=True)
class AuditContext:
    """Who and where, taken from the request."""

    actor_user_id: uuid.UUID | None = None
    actor_type: ActorType = "anonymous"
    ip: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class AuditEntry:
    action: str
    outcome: Outcome = "success"
    target_type: str | None = None
    target_id: str | None = None
    workspace_id: uuid.UUID | None = None
    client_org_id: uuid.UUID | None = None
    details: dict[str, Any] = field(default_factory=dict)


async def record(session: AsyncSession, ctx: AuditContext, entry: AuditEntry) -> None:
    """Appends one event in the caller's transaction (it commits or rolls back with it)."""
    await session.execute(
        _APPEND,
        {
            "actor_type": ctx.actor_type,
            "actor_user_id": ctx.actor_user_id,
            "action": entry.action,
            "outcome": entry.outcome,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "workspace_id": entry.workspace_id,
            "client_org_id": entry.client_org_id,
            "ip": ctx.ip,
            "request_id": ctx.request_id,
            "details": json.dumps(entry.details, default=str, sort_keys=True),
        },
    )
