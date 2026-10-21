"""Agent API schemas (never the ORM models)."""

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.ai.agents.spec import AgentSpec


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AgentCreate(_In):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    spec: AgentSpec
    comment: str = Field(default="", max_length=500)


class AgentUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    version: int = Field(description="Version courante (verrouillage optimiste)")


class AgentVersionCreate(_In):
    spec: AgentSpec
    comment: str = Field(default="", max_length=500)
    base_version_no: int | None = Field(
        default=None, description="Version éditée ; 409 si une autre a été créée depuis"
    )


class AgentTestIn(_In):
    input: dict[str, Any] = Field(default_factory=dict)
    version_no: int | None = Field(default=None, ge=1)


class AgentVersionOut(BaseModel):
    id: uuid.UUID
    version_no: int
    comment: str
    created_by: uuid.UUID | None
    created_at: datetime


class AgentVersionDetailOut(AgentVersionOut):
    spec: dict[str, Any]


class AgentOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    preset: str | None
    version: int
    active_version_no: int | None
    engine_mode: str | None
    tools: list[str]
    updated_at: datetime


class AgentDetailOut(AgentOut):
    active_spec: dict[str, Any] | None
    versions: list[AgentVersionOut]


class AgentRunOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID | None
    task: str | None
    agent_version_no: int | None
    context_type: str
    context_id: str | None
    status: str
    engine_kind: str | None
    model_requested: str | None
    model_served: str | None
    turns: int
    tool_calls: int
    input_tokens: int
    output_tokens: int
    cost_estimate_usd: Decimal
    injection_flag_count: int
    error: str | None
    refusal_category: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class AgentStepOut(BaseModel):
    seq: int
    type: str
    payload: dict[str, Any]
    created_at: datetime


class AgentRunDetailOut(AgentRunOut):
    input: dict[str, Any]
    output: dict[str, Any] | None
    sources: list[Any]
    injection_flags: list[Any]
    cache_read_tokens: int
    cache_write_tokens: int
    steps: list[AgentStepOut]


class AgentRunQueued(BaseModel):
    run_id: uuid.UUID
    status: str


class BudgetIn(_In):
    monthly_limit_usd: Decimal | None = Field(ge=0, le=100_000, decimal_places=2)
    hard_stop: bool = True


class SpendOut(BaseModel):
    period: date
    spent_usd: Decimal
    input_tokens: int
    output_tokens: int
    calls: int


class BudgetOut(BaseModel):
    monthly_limit_usd: Decimal | None
    hard_stop: bool
    period: date
    spent_usd: Decimal
    percent: int | None
    exhausted: bool
    alerts_sent: list[int]
    history: list[SpendOut]


class NeedOut(BaseModel):
    name: str
    level: Literal["ok", "degraded", "missing"]
    detail: str


class AgentCompatibilityOut(BaseModel):
    agent_id: uuid.UUID
    name: str
    engine_mode: str
    affected: bool
    compatible: bool
    needs: list[NeedOut]


class CompatibilityReportOut(BaseModel):
    model_row_id: uuid.UUID
    model_id: str
    compatible: bool
    agents: list[AgentCompatibilityOut]
