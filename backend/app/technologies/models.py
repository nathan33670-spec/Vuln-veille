"""Technology ORM model. Schema: migration 0006_watch."""

import uuid

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Technology(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "technologies"

    vendor: Mapped[str] = mapped_column(Text)
    product: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    cpe_prefixes: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    purls: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    category: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, default="active")
    merged_into: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("technologies.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
