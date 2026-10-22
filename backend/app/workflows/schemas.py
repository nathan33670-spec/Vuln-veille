"""API schemas of the workflow engine (never the ORM models)."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.workflows.expressions import MAX_EXPRESSION, MAX_TEMPLATE


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReferenceFieldOut(BaseModel):
    kind: str
    family: str | None
    connector_kinds: list[str]


class NodeTypeOut(BaseModel):
    type: str
    version: int
    label: str
    category: str
    queue: str
    inputs: list[str]
    outputs: list[str]
    params_schema: dict[str, Any]
    required_permissions: list[str]
    uses_egress: bool
    requires_approval_upstream: bool
    trigger_type: str | None
    reference_fields: dict[str, ReferenceFieldOut]


class WorkflowCreate(_In):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    graph: dict[str, Any] | None = None
    comment: str = Field(default="", max_length=500)


class WorkflowUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = Field(default=None, max_length=20)
    status: Literal["active", "paused", "archived"] | None = None
    version: int = Field(description="Version courante (verrouillage optimiste)")


class VersionCreate(_In):
    graph: dict[str, Any]
    comment: str = Field(default="", max_length=500)
    base_version_no: int | None = Field(
        default=None, description="Version éditée ; 409 si une autre a été publiée depuis"
    )


class VersionRestore(_In):
    comment: str = Field(default="", max_length=500)
    base_version_no: int | None = Field(
        default=None, description="Dernière version connue ; 409 si une autre a été publiée"
    )


class RunCreate(_In):
    input: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=100)


class ApprovalDecision(_In):
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=2000)


class VersionOut(BaseModel):
    id: uuid.UUID
    version_no: int
    comment: str
    graph_hash: str
    created_by: uuid.UUID | None
    created_at: datetime


class VersionDetailOut(VersionOut):
    graph: dict[str, Any]


class TriggerOut(BaseModel):
    id: uuid.UUID
    node_id: str
    type: str
    config: dict[str, Any]
    next_fire_at: datetime | None
    enabled: bool
    webhook_path: str | None = Field(
        default=None, description="Chemin du webhook (requêtes signées HMAC-SHA256)"
    )


class RunSummaryOut(BaseModel):
    id: uuid.UUID
    workflow_id: uuid.UUID
    version_no: int | None
    trigger_type: str
    status: str
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    stats: dict[str, Any]


class WorkflowOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    status: str
    tags: list[str]
    seed_key: str | None
    active_version_no: int | None
    latest_version_no: int | None
    version: int
    updated_at: datetime
    last_run: RunSummaryOut | None


class WorkflowDetailOut(WorkflowOut):
    versions: list[VersionOut]
    latest_graph: dict[str, Any] | None
    triggers: list[TriggerOut]


class WorkflowExport(BaseModel):
    format: Literal["vuln-veille.workflow/1"] = "vuln-veille.workflow/1"
    name: str
    description: str
    tags: list[str]
    graph: dict[str, Any]


class WorkflowImport(_In):
    format: Literal["vuln-veille.workflow/1"]
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    graph: dict[str, Any]


class NodeRunOut(BaseModel):
    node_id: str
    attempt: int
    status: str
    queue: str
    scheduled_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    input_count: int
    output_count: int
    output_truncated: bool
    error: str | None
    logs: list[Any]
    metrics: dict[str, Any]
    # AI engine calls made by the node (agents and AI tasks), and their estimated cost.
    ai_calls: int = 0
    ai_cost_usd: Decimal | None = None


class NodeRunDetailOut(NodeRunOut):
    output: dict[str, Any]


class ApprovalOut(BaseModel):
    node_id: str
    requested_at: datetime
    decision: str | None
    decided_by: uuid.UUID | None
    decided_at: datetime | None
    comment: str


class RunDetailOut(RunSummaryOut):
    mode: str
    test_node_id: str | None
    trigger_node_id: str
    triggered_by: uuid.UUID | None
    trigger_payload: dict[str, Any]
    cancel_requested: bool
    deadline_at: datetime | None
    node_runs: list[NodeRunOut]
    approvals: list[ApprovalOut]


class RunStarted(BaseModel):
    run_id: uuid.UUID
    created: bool


class WebhookSecretOut(BaseModel):
    """Shown once: the signing secret is write-only afterwards."""

    node_id: str
    trigger_id: uuid.UUID
    webhook_path: str
    secret: str


class ActivationOut(WorkflowDetailOut):
    webhook_secrets: list[WebhookSecretOut] = Field(default_factory=list)


class DraftIn(_In):
    graph: dict[str, Any]
    base_version_no: int | None = Field(
        default=None, description="Version dont part le brouillon (détection d'édition concurrente)"
    )


class DraftOut(BaseModel):
    graph: dict[str, Any]
    base_version_no: int | None
    latest_version_no: int | None
    stale: bool = Field(description="Une version a été publiée depuis le début du brouillon")
    updated_by: uuid.UUID | None
    updated_at: datetime
    errors: list[dict[str, Any]] = Field(description="Erreurs de validation du graphe (indicatif)")


class TestNodeIn(_In):
    node_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    graph: dict[str, Any] | None = Field(
        default=None,
        description="Graphe à tester ; par défaut le brouillon, sinon la dernière version",
    )
    inputs: dict[str, list[dict[str, Any]]] = Field(
        default_factory=dict,
        description="Éléments épinglés par port d'entrée ({json, meta}), par ex. une CVE réelle",
    )


class PreviewIn(_In):
    """An expression or a template evaluated on a sample item, as a node would."""

    expr: str | None = Field(default=None, min_length=1, max_length=MAX_EXPRESSION)
    tpl: str | None = Field(default=None, max_length=MAX_TEMPLATE)
    item: dict[str, Any] = Field(
        default_factory=dict, description="Élément d'exemple : {json, meta}"
    )

    @model_validator(mode="after")
    def _one(self) -> "PreviewIn":
        if (self.expr is None) == (self.tpl is None):
            raise ValueError("expr or tpl, exactly one")
        return self


class PreviewOut(BaseModel):
    value: Any = None
    error: str | None = None
    truncated: bool = False


class CveSampleOut(BaseModel):
    """A catalogue CVE as a workflow sees it: the NVD event, or the CVE record."""

    event: dict[str, Any]
    summary: dict[str, Any]


class NodeOutputOut(BaseModel):
    """A past output of a node, reusable as pinned data."""

    run_id: uuid.UUID
    mode: str
    status: str
    finished_at: datetime | None
    output_count: int
    version_no: int | None
