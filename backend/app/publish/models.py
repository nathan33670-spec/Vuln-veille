"""Publication ORM models (spec 05). Schema: migration 0017_publish_connectors."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import ARRAY, CIDR
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
