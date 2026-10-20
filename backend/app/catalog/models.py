"""Catalogue ORM models (spec 01). Schema: migration 0005_catalog."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Numeric, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class CveRecord(Base):
    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source_identifier: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vuln_status: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    base_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    severity: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    cpe_configurations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    cpe_criteria: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    kev: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    epss_score: Mapped[Decimal | None] = mapped_column(Numeric(6, 5))
    epss_percentile: Mapped[Decimal | None] = mapped_column(Numeric(6, 5))
    epss_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sources: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    from_backfill: Mapped[bool] = mapped_column(Boolean, default=False)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CveChange(Base):
    __tablename__ = "cve_changes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cve_records.cve_id", ondelete="CASCADE"))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    change_types: Mapped[list[str]] = mapped_column(ARRAY(Text))
    source: Mapped[str] = mapped_column(Text)
    diff: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class OutboxEvent(Base):
    """Events written in the same transaction as the change they announce (spec 02)."""

    __tablename__ = "outbox_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(Text)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
