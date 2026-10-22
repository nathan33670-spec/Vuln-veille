"""Evaluation bench API schemas."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaseIn(_In):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,19}$")
    input: dict[str, Any] = Field(
        default_factory=dict, description="Données ajoutées à l'entrée de l'agent"
    )
    expected: dict[str, Any] = Field(
        default_factory=dict,
        description="Champs clés attendus, validés par les analystes (ex. exploitation_status)",
    )
    notes: str = Field(default="", max_length=2000)


class CaseOut(BaseModel):
    id: uuid.UUID
    cve_id: str
    input: dict[str, Any]
    expected: dict[str, Any]
    notes: str
    validated_by: uuid.UUID | None
    updated_at: datetime


class RunIn(_In):
    agent_id: uuid.UUID
    model_row_id: uuid.UUID = Field(description="Modèle candidat")
    max_cost_usd: Decimal = Field(default=Decimal(5), gt=0, le=100, decimal_places=4)
    case_ids: list[uuid.UUID] | None = Field(
        default=None, max_length=200, description="Par défaut, tout le jeu de référence"
    )


class RunOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    model_row_id: uuid.UUID
    model_id: str
    status: str
    max_cost_usd: Decimal
    cases: int
    metrics: dict[str, Any]
    error: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class RunDetailOut(RunOut):
    results: list[dict[str, Any]]


class ComparisonOut(BaseModel):
    baseline: RunOut
    candidate: RunOut
    metrics: dict[str, Any]
    cases: list[dict[str, Any]]
