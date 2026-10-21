"""Node types: the contract between the engine and the code of each node (spec 02 §4).

Items flowing between nodes are ``{"json": {...}, "meta": {...}}``. ``meta`` carries
provenance (``source``, ``url``, ``fetched_at``), ``trust`` (``untrusted`` for anything
collected from outside) and lineage. Node code only reaches the outside world through
the capabilities of ``NodeContext``: no SQL session, environment or file system.
"""

import builtins
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict

from app.connectors.base import ConnectorContext
from app.core.narrow import expect
from app.iam.permissions import Permission

if TYPE_CHECKING:
    from app.workflows.repo import WorkspaceRepo

__all__ = ["expect"]  # re-exported for node modules

Item = dict[str, Any]
Outputs = dict[str, list[Item]]


class NodeCategory(StrEnum):
    TRIGGER = "trigger"
    SOURCE = "source"
    TRANSFORM = "transform"
    AI = "ai"
    VULN = "vuln"
    BULLETIN = "bulletin"
    OUTPUT = "output"
    CONTROL = "control"
    INTEGRATION = "integration"


class NodeParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class EmptyParams(NodeParams):
    pass


@dataclass(frozen=True)
class Reference:
    """Something a parameter points to, checked to belong to the same workspace."""

    kind: str  # "connector" for now (secrets go through connectors)
    id: uuid.UUID
    family: str | None = None
    kind_of_connector: str | None = None


def item(json: Mapping[str, Any], *, source: str, trust: str = "trusted", **meta: Any) -> Item:
    return {"json": dict(json), "meta": {"source": source, "trust": trust, **meta}}


class NodeError(Exception):
    """Expected failure of a node; ``code`` is safe to store and show (no data value)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code[:200]


class ConnectorAccess(Protocol):
    async def open(self, connector_id: uuid.UUID, kinds: tuple[str, ...]) -> ConnectorContext:
        """The connector's runtime context; raises NodeError when unusable."""


@dataclass
class RunInfo:
    id: uuid.UUID
    workflow_id: uuid.UUID
    trigger_type: str
    trigger_payload: dict[str, Any]
    workflow_name: str = ""


@dataclass
class NodeContext:
    workspace_id: uuid.UUID
    run: RunInfo
    node_id: str
    now: datetime
    repo: "WorkspaceRepo"
    connectors: ConnectorAccess
    upstream: dict[str, list[Item]] = field(default_factory=dict)
    logs: list[dict[str, Any]] = field(default_factory=list)
    # E-mails are sent after the node's transaction commits (at-least-once, idempotent).
    mails: list[tuple[str, str, str]] = field(default_factory=list)
    dry_run: bool = False

    def log(self, message: str, **data: Any) -> None:
        if len(self.logs) < 200:  # noqa: PLR2004 - bounded log per node run
            self.logs.append({"at": self.now.isoformat(), "message": message[:500], **data})

    def expression_context(self, entry: Item | None = None) -> dict[str, Any]:
        return {
            "json": (entry or {}).get("json", {}),
            "meta": (entry or {}).get("meta", {}),
            "run": {
                "id": str(self.run.id),
                "trigger": self.run.trigger_type,
                "payload": self.run.trigger_payload,
            },
            "nodes": {node: {"items": items} for node, items in self.upstream.items()},
        }


class NodeType(ABC):
    type: ClassVar[str]
    version: ClassVar[int] = 1
    label: ClassVar[str]
    category: ClassVar[NodeCategory]
    queue: ClassVar[str] = "default"
    Params: ClassVar[builtins.type[NodeParams]] = EmptyParams
    inputs: ClassVar[tuple[str, ...]] = ("in",)
    outputs: ClassVar[tuple[str, ...]] = ("out",)
    required_permissions: ClassVar[frozenset[Permission]] = frozenset()
    uses_egress: ClassVar[bool] = False
    # Nodes with an external effect that must be preceded by an approval on every path.
    requires_approval_upstream: ClassVar[bool] = False
    # Trigger nodes: the trigger type registered on activation.
    trigger_type: ClassVar[str | None] = None
    # Runs even when its inputs carry no item (sources reading on a schedule).
    runs_without_items: ClassVar[bool] = False
    # Pauses the run until an analyst decides (control.approval).
    waits_for_approval: ClassVar[bool] = False

    def references(self, params: NodeParams) -> list[Reference]:
        return []

    @abstractmethod
    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        """Returns items per output port."""


class RegistrationError(TypeError):
    pass


_REGISTRY: dict[str, type[NodeType]] = {}


def register_node(cls: type[NodeType]) -> type[NodeType]:
    if cls.type in _REGISTRY and _REGISTRY[cls.type] is not cls:
        raise RegistrationError(f"node type {cls.type!r} registered twice")
    if cls.queue not in ("default", "collect", "ai", "publish"):
        raise RegistrationError(f"{cls.type}: unknown queue {cls.queue}")
    if cls.category == NodeCategory.TRIGGER and (cls.inputs or not cls.trigger_type):
        raise RegistrationError(f"{cls.type}: triggers have no input and a trigger type")
    _REGISTRY[cls.type] = cls
    return cls


def node_types() -> Mapping[str, type[NodeType]]:
    from app.workflows import nodes  # noqa: F401, PLC0415 - registers the built-in nodes

    return dict(_REGISTRY)
