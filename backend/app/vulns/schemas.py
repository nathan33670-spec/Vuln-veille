"""Vulnerability and CVE catalogue API schemas.

Free text written by analysts (rationale, comments) is Markdown, stored as typed and
rendered by the interface through the sanitising renderer only (SECURITY.md §4.5).
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, Field, HttpUrl, model_validator

from app.iam.schemas import StrictIn
from app.watch.collect import clean_text

Status = Literal["new", "triage", "qualified", "rejected", "duplicate", "monitoring"]
Priority = Literal["P1", "P2", "P3", "P4"]
Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,19}$")]


def _clean(limit: int) -> AfterValidator:
    return AfterValidator(lambda v: clean_text(v, limit))


Title = Annotated[str, Field(min_length=1, max_length=300), _clean(300)]
Markdown = Annotated[str, Field(max_length=20000), _clean(20000)]
Aliases = Annotated[list[Annotated[str, Field(min_length=1, max_length=100)]], Field(max_length=50)]


class VulnerabilityCreate(StrictIn):
    cve_id: CveId | None = None
    title: Title | None = None
    summary: Markdown = ""
    aliases: Aliases = Field(default_factory=list)

    @model_validator(mode="after")
    def _cve_or_title(self) -> "VulnerabilityCreate":
        if self.cve_id is None and not self.title:
            raise ValueError("a CVE identifier or a title is required")
        return self


class VulnerabilityUpdate(StrictIn):
    version: int
    title: Title | None = None
    summary: Markdown | None = None
    aliases: Aliases | None = None
    exploitation_status: (
        Literal["unknown", "poc_public", "exploited_itw", "not_exploitable"] | None
    ) = None
    patch_status: Literal["unknown", "available", "partial", "none", "workaround"] | None = None
    duplicate_of_ref: str | None = Field(default=None, pattern=r"^VV-\d{4}-\d{4,}$")


class AssessmentIn(StrictIn):
    version: int = Field(description="0 when the team has no assessment yet.")
    status: Status | None = None
    priority: Priority | None = None
    severity: Severity | None = None
    assignee_id: uuid.UUID | None = None
    rationale: Markdown | None = None


class AdoptIn(StrictIn):
    from_workspace: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")


class CommentIn(StrictIn):
    body: Annotated[str, Field(min_length=1, max_length=20000), _clean(20000)]


class EvidenceIn(StrictIn):
    url: HttpUrl
    title: Annotated[str, Field(max_length=500), _clean(500)] = ""
    kind: Literal["advisory", "poc", "exploit", "patch", "discussion", "mention", "news"]
    note: Annotated[str, Field(max_length=2000), _clean(2000)] = ""


class AssessmentOut(BaseModel):
    id: uuid.UUID
    workspace: str
    status: str
    priority: str | None
    severity: str | None
    assignee_id: uuid.UUID | None
    rationale: str
    qualified_at: datetime | None
    qualified_by: uuid.UUID | None
    adopted_from: str | None
    version: int
    updated_at: datetime


class VulnerabilitySummaryOut(BaseModel):
    id: uuid.UUID
    ref: str
    cve_id: str | None
    title: str
    severity: str | None
    base_score: Decimal | None
    kev: bool
    epss_score: Decimal | None
    exploitation_status: str
    patch_status: str
    first_seen_at: datetime
    assessments: list[AssessmentOut]


class VulnerabilityPage(BaseModel):
    items: list[VulnerabilitySummaryOut]
    total: int


class TechnologyLinkOut(BaseModel):
    technology_id: uuid.UUID
    display_name: str
    vendor: str
    product: str
    matched_by: str


class EvidenceOut(BaseModel):
    id: uuid.UUID
    kind: str
    note: str
    workspace: str
    added_by_type: str
    created_at: datetime
    url: str | None
    title: str
    source_type: str
    trust: str


class AnalysisOut(BaseModel):
    id: uuid.UUID
    workspace: str
    content: dict[str, Any]
    injection_flags: list[Any]
    created_at: datetime


class TimelineEventOut(BaseModel):
    type: str
    workspace: str | None
    actor_type: str
    actor_user_id: uuid.UUID | None
    data: dict[str, Any]
    occurred_at: datetime


class CveOut(BaseModel):
    cve_id: str
    published_at: datetime | None
    last_modified_at: datetime | None
    vuln_status: str | None
    description: str
    severity: str | None
    base_score: Decimal | None
    cvss: dict[str, Any]
    cwes: list[str]
    references: list[dict[str, Any]]
    cpe_criteria: list[str]
    kev: dict[str, Any] | None
    epss_score: Decimal | None
    epss_percentile: Decimal | None
    sources: list[str]
    first_seen_at: datetime
    vulnerability_ref: str | None = None
    scope_decision: str | None = None
    scope_reasons: list[str] = Field(default_factory=list)


class VulnerabilityDetailOut(VulnerabilitySummaryOut):
    summary: str
    aliases: list[str]
    duplicate_of_ref: str | None
    origin: str
    version: int
    cve: CveOut | None
    technologies: list[TechnologyLinkOut]
    evidence: list[EvidenceOut]
    analyses: list[AnalysisOut]
    timeline: list[TimelineEventOut]


class CommentOut(BaseModel):
    id: uuid.UUID
    author_id: uuid.UUID | None
    body: str
    created_at: datetime


class CvePage(BaseModel):
    items: list[CveOut]
    total: int


class CveChangeOut(BaseModel):
    detected_at: datetime
    change_types: list[str]
    source: str
    diff: dict[str, Any]


class CveDetailOut(CveOut):
    changes: list[CveChangeOut]


class SyncStatusOut(BaseModel):
    kind: str
    name: str
    enabled: bool
    last_success_at: datetime | None
    last_check_at: datetime | None
    last_error: str | None
    consecutive_failures: int
    position: dict[str, Any]
