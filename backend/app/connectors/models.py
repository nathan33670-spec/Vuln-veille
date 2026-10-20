"""Connector ORM models (spec 01). Schema: migration 0004_connectors."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Connector(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "connectors"

    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    family: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    secret_refs: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    quotas: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    usage_current_period: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    egress_domains: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    allow_private_network: Mapped[bool] = mapped_column(Boolean, default=False)
    private_network_cidrs: Mapped[list[str]] = mapped_column(ARRAY(CIDR), default=list)
    private_network_approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    private_network_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    data_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class ConnectorCursor(Base):
    """Synchronisation position of a connector, per stream (e.g. NVD ``cves``)."""

    __tablename__ = "connector_cursors"

    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"), primary_key=True
    )
    stream: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
