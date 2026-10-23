"""Each client user chooses to receive the bulletins by e-mail (spec 06 §2, Q44)."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.iam.deps import DB, require
from app.iam.permissions import Permission
from app.iam.principal import Principal


class NotificationPreference(Base):
    __tablename__ = "portal_notification_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    email_bulletins: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PreferencesOut(BaseModel):
    email_bulletins: bool


class PreferencesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_bulletins: bool


Reader = Annotated[Principal, Depends(require(Permission.PORTAL_BULLETINS_READ))]


def build_preferences_router() -> APIRouter:
    router = APIRouter(prefix="/me/notifications", tags=["account"])

    @router.get("", response_model=PreferencesOut)
    async def get_preferences(principal: Reader, db: DB) -> PreferencesOut:
        row = await db.get(NotificationPreference, principal.user_id)
        return PreferencesOut(email_bulletins=bool(row and row.email_bulletins))

    @router.put("", response_model=PreferencesOut)
    async def put_preferences(body: PreferencesIn, principal: Reader, db: DB) -> PreferencesOut:
        """Bulletins by e-mail: at each publication and each published update (Q44),
        with the PDF attached (Q45)."""
        moment = datetime.now(UTC)
        await db.execute(
            insert(NotificationPreference)
            .values(user_id=principal.user_id, email_bulletins=body.email_bulletins,
                    updated_at=moment)
            .on_conflict_do_update(
                index_elements=["user_id"],
                set_={"email_bulletins": body.email_bulletins, "updated_at": moment},
            )
        )  # fmt: skip
        await db.commit()
        return PreferencesOut(email_bulletins=body.email_bulletins)

    return router
