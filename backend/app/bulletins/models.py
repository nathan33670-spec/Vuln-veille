"""Bulletin ORM models. Schema: migration 0015_bulletin_templates."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin

_USER = "users.id"


class BulletinTemplate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "bulletin_templates"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    name: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, default="draft")
    active_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletin_template_versions.id", use_alter=True)
    )
    seed_key: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)


class BulletinTemplateVersion(UUIDPrimaryKeyMixin, Base):
    """Immutable: a template change is a new version."""

    __tablename__ = "bulletin_template_versions"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bulletin_templates.id", ondelete="CASCADE")
    )
    version_no: Mapped[int] = mapped_column(Integer)
    spec: Mapped[dict[str, Any]] = mapped_column(JSONB)
    language: Mapped[str] = mapped_column(Text)
    priority: Mapped[int] = mapped_column(Integer)
    comment: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BulletinSettings(Base):
    __tablename__ = "bulletin_settings"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    ref_prefix: Mapped[str] = mapped_column(Text)
    review_required: Mapped[bool] = mapped_column(Boolean, default=False)
    default_template_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletin_templates.id", ondelete="SET NULL")
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    version: Mapped[int] = mapped_column(Integer, default=1)
