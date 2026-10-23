"""Publication ORM models (spec 05). Schema: migration 0017_publish_connectors."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

_USER = "users.id"


class PrivateNetworkRequest(Base):
    """A connector's request to reach private ranges, and the admin's decision (Q41)."""

    __tablename__ = "private_network_requests"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connectors.id", ondelete="CASCADE"))
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    connector_name: Mapped[str] = mapped_column(Text)
    hosts: Mapped[list[str]] = mapped_column(ARRAY(Text))
    cidrs: Mapped[list[str]] = mapped_column(ARRAY(CIDR))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str] = mapped_column(Text, default="")


class PublicationTarget(Base):
    """What a connector holds of a bulletin: its remote id, and who pushed it first."""

    __tablename__ = "publication_targets"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    bulletin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bulletins.id", ondelete="CASCADE"), primary_key=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"), primary_key=True
    )
    remote_id: Mapped[str | None] = mapped_column(Text)
    first_pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_pushed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(_USER, ondelete="SET NULL")
    )
    last_rev_no: Mapped[int | None] = mapped_column(Integer)
    last_status: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PushRecord(Base):
    """One push of a bulletin (or of the test example) to a connector."""

    __tablename__ = "publications"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    bulletin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletins.id", ondelete="CASCADE")
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connectors.id", ondelete="CASCADE"))
    connector_version: Mapped[int] = mapped_column(Integer)
    revision_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("bulletin_revisions.id"))
    rev_no: Mapped[int | None] = mapped_column(Integer)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False)
    origin: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    node_run_id: Mapped[uuid.UUID | None] = mapped_column()
    status: Mapped[str] = mapped_column(Text)
    mode: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str | None] = mapped_column(Text)
    remote_id: Mapped[str | None] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PushAttempt(Base):
    __tablename__ = "publication_attempts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    publication_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("publications.id", ondelete="CASCADE")
    )
    attempt_no: Mapped[int] = mapped_column(Integer)
    request: Mapped[dict[str, Any]] = mapped_column(JSONB)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_excerpt: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
