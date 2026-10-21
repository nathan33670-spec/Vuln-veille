"""Preferred AI engine at three levels (spec 07 §4.1): platform (administrators),
overridden per workspace, then per agent (inherit or pin, phase 4 step 4.7)."""

import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.models import AIEnginePreference, AIModel
from app.ai.types import AIConfigurationError

Source = Literal["agent", "workspace", "platform"]


@dataclass(frozen=True)
class Resolved:
    model: AIModel
    source: Source


def usable(model: AIModel | None, workspace_id: uuid.UUID | None) -> bool:
    return (
        model is not None
        and model.enabled
        and model.connector_enabled
        and model.workspace_id in (None, workspace_id)
    )


async def preference(db: AsyncSession, workspace_id: uuid.UUID | None) -> AIModel | None:
    condition = (
        AIEnginePreference.workspace_id.is_(None)
        if workspace_id is None
        else AIEnginePreference.workspace_id == workspace_id
    )
    row = (await db.execute(select(AIEnginePreference).where(condition))).scalar_one_or_none()
    return await db.get(AIModel, row.model_row_id) if row is not None else None


async def resolve(
    db: AsyncSession, workspace_id: uuid.UUID, pinned: uuid.UUID | None = None
) -> Resolved:
    """The engine an agent of ``workspace_id`` uses; refuses an unusable choice."""
    if pinned is not None:
        model = await db.get(AIModel, pinned)
        if not usable(model, workspace_id):
            raise AIConfigurationError("pinned_engine_unavailable")
        assert model is not None  # noqa: S101 - checked by usable()
        return Resolved(model, "agent")
    for scope, source in ((workspace_id, "workspace"), (None, "platform")):
        model = await preference(db, scope)
        if model is not None:
            if not usable(model, workspace_id):
                raise AIConfigurationError(f"{source}_engine_unavailable")
            return Resolved(model, source)  # type: ignore[arg-type]
    raise AIConfigurationError("no_engine_configured")


async def set_preference(
    db: AsyncSession, workspace_id: uuid.UUID | None, model: AIModel | None, actor: uuid.UUID
) -> None:
    condition = (
        AIEnginePreference.workspace_id.is_(None)
        if workspace_id is None
        else AIEnginePreference.workspace_id == workspace_id
    )
    row = (
        await db.execute(select(AIEnginePreference).where(condition).with_for_update())
    ).scalar_one_or_none()
    if model is None:
        if row is not None:
            await db.delete(row)
        return
    if row is None:
        db.add(
            AIEnginePreference(
                id=uuid.uuid4(), workspace_id=workspace_id, model_row_id=model.id, changed_by=actor
            )
        )
    else:
        row.model_row_id, row.changed_by = model.id, actor
    await db.flush()
