"""AI engine API schemas."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel

from app.iam.schemas import StrictIn


class AIModelOut(BaseModel):
    id: uuid.UUID
    connector_id: uuid.UUID
    connector_kind: str
    connector_name: str
    scope: str
    model_id: str
    display_name: str
    enabled: bool
    usable: bool
    declared: dict[str, Any]
    verified: dict[str, Any] | None
    verified_at: datetime | None
    checks: dict[str, Any]
    data_classes: list[str]
    location: str
    price_input_per_mtok: Decimal | None
    price_output_per_mtok: Decimal | None


class EngineChoiceIn(StrictIn):
    model_row_id: uuid.UUID


class EnginePreferenceOut(BaseModel):
    platform: AIModelOut | None
    workspace: AIModelOut | None
    effective: AIModelOut | None
    source: str | None
