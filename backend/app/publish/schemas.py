"""API schemas of publication connectors (spec 05): never the ORM, never a secret."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DryRunIn(_In):
    bulletin_id: uuid.UUID
    remote_id: str | None = Field(
        default=None, max_length=200, description="Simule une mise à jour (identifiant distant)"
    )


class PreparedOut(BaseModel):
    """A request as it would be sent: credentials masked."""

    method: str
    url: str
    headers: dict[str, str]
    body: str
    mode: str


class MappingPreviewIn(_In):
    config: dict[str, Any] = Field(description="Configuration du connecteur, même non enregistrée")
    bulletin_id: uuid.UUID | None = Field(
        default=None, description="Bulletin validé ou publié ; sinon un exemple fictif"
    )


class MappingPreviewOut(BaseModel):
    valid: bool
    errors: list[dict[str, Any]]
    payload: Any = None
    request: PreparedOut | None = None
    paths: list[str]
    sample: bool


class TargetOut(BaseModel):
    """A connector a bulletin can be pushed to (the workspace's, or a global one)."""

    id: uuid.UUID
    name: str
    kind: str
    scope: Literal["workspace", "global"]
    enabled: bool
    health: str
    body_format: str | None


class PrivateNetworkIn(_In):
    cidrs: list[str] = Field(min_length=1, max_length=10)
    reason: str = Field(min_length=1, max_length=1000)


class PrivateNetworkRequestOut(BaseModel):
    id: uuid.UUID
    connector_id: uuid.UUID
    workspace_slug: str | None
    connector_name: str
    hosts: list[str]
    cidrs: list[str]
    reason: str
    status: str
    requested_by: uuid.UUID | None
    requested_at: datetime
    decided_by: uuid.UUID | None
    decided_at: datetime | None
    decision_note: str


class DecisionIn(_In):
    approve: bool
    note: str = Field(default="", max_length=1000)


class RevokeIn(_In):
    note: str = Field(default="", max_length=1000)
