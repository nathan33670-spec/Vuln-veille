"""API schemas of bulletin templates and settings (never the ORM models)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TemplateCreate(_In):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    spec: dict[str, Any]
    comment: str = Field(default="", max_length=500)


class TemplateUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    status: str | None = Field(default=None, pattern=r"^(active|archived)$")
    version: int = Field(description="Version lue ; 409 si le modèle a changé depuis")


class TemplateVersionCreate(_In):
    spec: dict[str, Any]
    comment: str = Field(default="", max_length=500)
    base_version_no: int | None = Field(
        default=None, description="Version éditée ; 409 si une autre a été créée depuis"
    )


class TemplateVersionOut(BaseModel):
    id: uuid.UUID
    version_no: int
    language: str
    priority: int
    comment: str
    created_by: uuid.UUID | None
    created_at: datetime


class TemplateVersionDetailOut(TemplateVersionOut):
    spec: dict[str, Any]


class TemplateOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    status: str
    seed_key: str | None
    active_version_no: int | None
    latest_version_no: int | None
    language: str | None
    priority: int | None
    tlp: str | None
    rule_count: int
    is_default: bool
    updated_at: datetime
    version: int


class TemplateDetailOut(TemplateOut):
    versions: list[TemplateVersionOut]
    active_spec: dict[str, Any] | None
    latest_spec: dict[str, Any] | None


class PreviewIn(_In):
    spec: dict[str, Any]
    vulnerability_id: uuid.UUID | None = Field(
        default=None, description="Vulnérabilité réelle pour les champs calculés"
    )
    fields: dict[str, Any] | None = Field(
        default=None, description="Valeurs de champs à rendre, à la place des exemples"
    )


class PreviewOut(BaseModel):
    fields: dict[str, Any]
    markdown: str
    html: str
    matches: bool | None = Field(description="Les règles du modèle retiennent cette vulnérabilité")
    reasons: list[str]


class MatchOut(BaseModel):
    template_id: uuid.UUID
    template_name: str
    version_no: int
    language: str
    rule_index: int | None = Field(description="Règle satisfaite ; null : modèle par défaut")
    reasons: list[str]


class SettingsOut(BaseModel):
    ref_prefix: str
    review_required: bool
    default_template_id: uuid.UUID | None
    updated_at: datetime
    version: int


class SettingsIn(_In):
    ref_prefix: str = Field(pattern=r"^[A-Z][A-Z0-9-]{0,15}$")
    review_required: bool
    default_template_id: uuid.UUID | None
    version: int
