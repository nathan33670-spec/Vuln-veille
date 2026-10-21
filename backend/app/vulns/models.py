"""Vulnerability ORM models. Schema: migration 0007_vulnerabilities."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import BigInteger, DateTime, FetchedValue, ForeignKey, Integer, Numeric, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin

_USER = "users.id"


class Vulnerability(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerabilities"

    ref: Mapped[str] = mapped_column(Text, server_default=FetchedValue())
    cve_id: Mapped[str | None] = mapped_column(Text)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="")
    duplicate_of: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vulnerabilities.id"))
    exploitation_status: Mapped[str] = mapped_column(Text, default="unknown")
    patch_status: Mapped[str] = mapped_column(Text, default="unknown")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    origin: Mapped[str] = mapped_column(Text)
    origin_workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    version: Mapped[int] = mapped_column(Integer, default=1)


class Assessment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_assessments"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    status: Mapped[str] = mapped_column(Text, default="new")
    priority: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(Text)
    cvss_override: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    rationale: Mapped[str] = mapped_column(Text, default="")
    qualified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    qualified_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    copied_from_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("vulnerability_assessments.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class VulnerabilityTechnology(Base):
    __tablename__ = "vulnerability_technologies"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id"), primary_key=True
    )
    technology_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("technologies.id"), primary_key=True
    )
    matched_by: Mapped[str] = mapped_column(Text)
    confidence: Mapped[Decimal] = mapped_column(Numeric(3, 2), default=Decimal(1))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Evidence(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "vulnerability_evidence"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    collected_item_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("collected_items.id"))
    kind: Mapped[str] = mapped_column(Text)
    note: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[Decimal] = mapped_column(Numeric(3, 2), default=Decimal(1))
    added_by_type: Mapped[str] = mapped_column(Text)
    added_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Analysis(UUIDPrimaryKeyMixin, Base):
    """AI synthesis (generated in phase 4): validated JSON, never rendered as markup."""

    __tablename__ = "vulnerability_analyses"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column()
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)
    injection_flags: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Comment(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "vulnerability_comments"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VulnerabilityEvent(Base):
    __tablename__ = "vulnerability_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    type: Mapped[str] = mapped_column(Text)
    actor_type: Mapped[str] = mapped_column(Text)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
