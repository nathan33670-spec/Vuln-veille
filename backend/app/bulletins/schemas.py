"""API schemas of bulletin templates and settings (never the ORM models)."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.bulletins.spec import Tlp


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
    tlp: Tlp | None = Field(default=None, description="Marquage du bulletin, sinon celui du modèle")


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


CsafCategory = Literal["coordinator", "discoverer", "other", "translator", "user", "vendor"]


class SettingsOut(BaseModel):
    ref_prefix: str
    review_required: bool
    default_template_id: uuid.UUID | None
    csaf_publisher_name: str
    csaf_publisher_namespace: str
    csaf_publisher_category: str
    updated_at: datetime
    version: int


class SettingsIn(_In):
    ref_prefix: str = Field(pattern=r"^[A-Z][A-Z0-9-]{0,15}$")
    review_required: bool
    default_template_id: uuid.UUID | None
    # CSAF publisher (Q42); left out: unchanged.
    csaf_publisher_name: str | None = Field(default=None, max_length=200)
    csaf_publisher_namespace: str | None = Field(
        default=None, max_length=500, pattern=r"^(https://[^\s]+)?$"
    )
    csaf_publisher_category: CsafCategory | None = None
    version: int


class DraftRequestIn(_In):
    vulnerability_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,19}$")
    urls: list[str] = Field(default_factory=list, max_length=20)
    text: str = Field(default="", max_length=20000)
    template_id: uuid.UUID | None = Field(
        default=None, description="Modèle imposé ; sinon choisi par les règles"
    )
    language: str | None = Field(default=None, pattern=r"^(fr|en)$")
    extra_instructions: str = Field(default="", max_length=2000)


class DraftRequestOut(BaseModel):
    id: uuid.UUID
    kind: str
    status: str
    progress: list[dict[str, Any]]
    bulletin_id: uuid.UUID | None
    agent_run_id: uuid.UUID | None
    error: str | None
    template_name: str | None
    template_version_no: int | None
    selection_reasons: list[str]
    requested_by: uuid.UUID | None
    created_at: datetime
    finished_at: datetime | None


class RegenerateIn(_In):
    field: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    instructions: str = Field(default="", max_length=2000)


class TranslateIn(_In):
    language: str = Field(pattern=r"^(fr|en)$")
    template_id: uuid.UUID | None = None


class RevisionIn(_In):
    fields: dict[str, Any]
    change_note: str = Field(default="", max_length=500)
    base_rev_no: int = Field(description="Révision éditée ; 409 si une autre a été créée depuis")


class BulletinUpdate(_In):
    tlp: str | None = Field(default=None, pattern=r"^(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")
    audience_type: str | None = Field(default=None, pattern=r"^(all_clients|selected)$")
    audience_org_ids: list[uuid.UUID] | None = Field(default=None, max_length=500)
    version: int


class TransitionIn(_In):
    comment: str = Field(default="", max_length=1000)
    version: int


class WithdrawIn(_In):
    reason: str = Field(min_length=1, max_length=1000)
    version: int


class RevisionSummaryOut(BaseModel):
    rev_no: int
    created_by_type: str
    created_by: uuid.UUID | None
    agent_run_id: uuid.UUID | None
    change_note: str
    content_hash: str
    created_at: datetime


class RevisionOut(RevisionSummaryOut):
    fields: dict[str, Any]
    rendered_markdown: str
    rendered_html: str


class LinkedVulnerabilityOut(BaseModel):
    id: uuid.UUID
    ref: str
    cve_id: str | None
    title: str


class LinkedTechnologyOut(BaseModel):
    id: uuid.UUID
    display_name: str


class LinkedBulletinOut(BaseModel):
    id: uuid.UUID
    ref: str
    language: str
    status: str


class AudienceOut(BaseModel):
    id: uuid.UUID
    name: str


class BulletinOut(BaseModel):
    id: uuid.UUID
    ref: str
    title: str
    status: str
    severity: str | None
    tlp: str
    language: str
    workspace_slug: str
    own: bool
    author_id: uuid.UUID | None
    current_rev_no: int | None
    published_rev_no: int | None
    published_at: datetime | None
    updated_at: datetime
    version: int


class BulletinDetailOut(BulletinOut):
    audience_type: str
    audience_org_ids: list[uuid.UUID]
    # Unset for the other team: templates are workspace data.
    template_id: uuid.UUID | None
    template_name: str | None
    template_version_no: int | None
    template_spec: dict[str, Any] | None
    review_required: bool
    submitted_by: uuid.UUID | None
    reviewer_id: uuid.UUID | None
    approved_at: datetime | None
    withdrawn_reason: str | None
    current: RevisionOut | None
    revisions: list[RevisionSummaryOut]
    vulnerabilities: list[LinkedVulnerabilityOut]
    technologies: list[LinkedTechnologyOut]
    translation_of: LinkedBulletinOut | None
    translations: list[LinkedBulletinOut]
