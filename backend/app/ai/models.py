"""AI engine ORM models. Schema: migration 0009_ai_engines."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, UUIDPrimaryKeyMixin


class AIModel(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ai_models"

    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connectors.id", ondelete="CASCADE"))
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    connector_kind: Mapped[str] = mapped_column(Text)
    connector_name: Mapped[str] = mapped_column(Text)
    connector_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    model_id: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    declared: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    verified: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    checks: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    data_classes: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    location: Mapped[str] = mapped_column(Text)
    price_input_per_mtok: Mapped[Decimal | None] = mapped_column(Numeric(10, 4))
    price_output_per_mtok: Mapped[Decimal | None] = mapped_column(Numeric(10, 4))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AIEnginePreference(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ai_engine_preferences"

    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    model_row_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ai_models.id", ondelete="CASCADE"))
    changed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
