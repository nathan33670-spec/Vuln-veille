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
    # CSAF publisher (Q42): the export is refused while name or namespace is empty.
    csaf_publisher_name: Mapped[str] = mapped_column(Text, default="")
    csaf_publisher_namespace: Mapped[str] = mapped_column(Text, default="")
    csaf_publisher_category: Mapped[str] = mapped_column(Text, default="coordinator")
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    version: Mapped[int] = mapped_column(Integer, default=1)


class BulletinRefCounter(Base):
    __tablename__ = "bulletin_ref_counters"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_no: Mapped[int] = mapped_column(Integer)


class Bulletin(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "bulletins"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    ref: Mapped[str] = mapped_column(Text)
    language: Mapped[str] = mapped_column(Text)
    translation_of: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("bulletins.id"))
    title: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(Text)
    tlp: Mapped[str] = mapped_column(Text)
    audience_type: Mapped[str] = mapped_column(Text, default="all_clients")
    template_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bulletin_template_versions.id")
    )
    current_revision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletin_revisions.id", use_alter=True)
    )
    published_revision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletin_revisions.id", use_alter=True)
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    submitted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_reason: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)


class BulletinRevision(UUIDPrimaryKeyMixin, Base):
    """Immutable: an edit is a new revision."""

    __tablename__ = "bulletin_revisions"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    bulletin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("bulletins.id", ondelete="CASCADE"))
    rev_no: Mapped[int] = mapped_column(Integer)
    fields: Mapped[dict[str, Any]] = mapped_column(JSONB)
    rendered_markdown: Mapped[str] = mapped_column(Text)
    rendered_html: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(Text)
    created_by_type: Mapped[str] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column()
    change_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BulletinVulnerability(Base):
    __tablename__ = "bulletin_vulnerabilities"

    bulletin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bulletins.id", ondelete="CASCADE"), primary_key=True
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id"), primary_key=True
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))


class BulletinTechnology(Base):
    __tablename__ = "bulletin_technologies"

    bulletin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bulletins.id", ondelete="CASCADE"), primary_key=True
    )
    technology_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("technologies.id"), primary_key=True
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))


class BulletinAudience(Base):
    __tablename__ = "bulletin_audiences"

    bulletin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bulletins.id", ondelete="CASCADE"), primary_key=True
    )
    client_org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("client_organizations.id", ondelete="CASCADE"), primary_key=True
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))


class DraftRequest(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "draft_requests"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    kind: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey(_USER, ondelete="SET NULL"))
    input: Mapped[dict[str, Any]] = mapped_column(JSONB)
    template_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletin_template_versions.id")
    )
    extra_instructions: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text)
    progress: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    bulletin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bulletins.id", ondelete="SET NULL")
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column()
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
