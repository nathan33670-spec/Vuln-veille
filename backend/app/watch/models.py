"""Watch ORM models. Schema: migration 0006_watch."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin


class WatchScope(Base):
    __tablename__ = "watch_scopes"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    mode: Mapped[str] = mapped_column(Text, default="scoped")
    technology_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    vendors: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    keywords: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    cvss_min: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    include_unscored: Mapped[str] = mapped_column(Text, default="wait")
    always_include_kev: Mapped[bool] = mapped_column(Boolean, default=True)
    cwe_include: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    cwe_exclude: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WatchSource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "watch_sources"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    name: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    trust_level: Mapped[str] = mapped_column(Text, default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class CollectedItem(UUIDPrimaryKeyMixin, Base):
    """Anything read from outside: always untrusted, never interpreted (SECURITY.md)."""

    __tablename__ = "collected_items"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    run_id: Mapped[uuid.UUID | None] = mapped_column()
    node_id: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[str] = mapped_column(Text)
    source_ref: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str | None] = mapped_column(Text)
    url_hash: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text, default="")
    content_text: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str] = mapped_column(Text)
    cve_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    language: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    trust: Mapped[str] = mapped_column(Text, default="untrusted")
