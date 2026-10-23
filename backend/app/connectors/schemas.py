"""Connector API schemas. Configurations are non-secret by construction (base.py)."""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.connectors.base import Quotas
from app.iam.schemas import StrictIn

Name = Annotated[str, Field(min_length=1, max_length=100)]
SlotRefs = Annotated[dict[str, uuid.UUID], Field(max_length=16)]


class SecretSlotOut(BaseModel):
    name: str
    label: str
    required: bool


class ConnectorTypeOut(BaseModel):
    kind: str
    family: str
    label: str
    scopes: list[str]
    cost_class: str
    config_schema: dict[str, Any]
    secret_slots: list[SecretSlotOut]
    egress_domains: list[str]
    default_quotas: Quotas


class ConnectorCreate(StrictIn):
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    name: Name
    config: dict[str, Any] = Field(default_factory=dict)
    secret_refs: SlotRefs = Field(default_factory=dict)
    quotas: dict[str, Any] | None = None
    enabled: bool = True


class ConnectorUpdate(StrictIn):
    version: int = Field(description="Current version (optimistic locking).")
    name: Name | None = None
    config: dict[str, Any] | None = None
    secret_refs: SlotRefs | None = None
    quotas: dict[str, Any] | None = None
    enabled: bool | None = None


class ConnectorOut(BaseModel):
    id: uuid.UUID
    family: str
    kind: str
    name: str
    config: dict[str, Any]
    secret_refs: dict[str, uuid.UUID]
    quotas: Quotas
    egress_domains: list[str]
    enabled: bool
    health: str
    last_check_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    consecutive_failures: int
    allow_private_network: bool
    private_network_cidrs: list[str] = Field(
        default_factory=list, description="Plages demandées ; actives après approbation"
    )
    version: int
    created_at: datetime
    updated_at: datetime


class CheckQueuedOut(BaseModel):
    queued: bool = True


class UsageOut(BaseModel):
    """Requests counted in the current minute, UTC day and UTC month."""

    minute: int
    day: int
    month: int
    quotas: Quotas
