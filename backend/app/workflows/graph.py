"""Workflow graph format (schema_version 1) and its validation (spec 02 §2).

Validation runs when a version is saved; errors are a list of ``{path, code}`` so the
editor can point at the faulty node or field without echoing submitted values.
"""

import hashlib
import json
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.iam.permissions import Permission
from app.workflows.base import NodeCategory, NodeParams, NodeType, Reference, node_types

MAX_NODES = 200
MAX_EDGES = 1000
MAX_PARAMS_BYTES = 64 * 1024
APPROVAL_TYPE = "control.approval"
NodeId = str


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Retry(_Strict):
    max_attempts: int = Field(default=1, ge=1, le=10)
    backoff_seconds: int = Field(default=30, ge=0, le=3600)


class NodeSettings(_Strict):
    retry: Retry = Field(default_factory=Retry)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    on_error: Literal["stop", "continue", "route"] = "stop"


class Position(_Strict):
    x: float = 0
    y: float = 0


class GraphNode(_Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    type: str = Field(pattern=r"^[a-z]+\.[a-z0-9_]+$")
    type_version: int = Field(default=1, ge=1)
    name: str = Field(default="", max_length=120)
    params: dict[str, Any] = Field(default_factory=dict)
    settings: NodeSettings = Field(default_factory=NodeSettings)
    position: Position = Field(default_factory=Position)


class Endpoint(_Strict):
    node: str
    port: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")


class GraphEdge(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    source: Endpoint = Field(alias="from")
    target: Endpoint = Field(alias="to")


class Graph(_Strict):
    schema_version: Literal[1] = 1
    nodes: list[GraphNode] = Field(max_length=MAX_NODES)
    edges: list[GraphEdge] = Field(default_factory=list, max_length=MAX_EDGES)

    def node(self, node_id: str) -> GraphNode:
        return next(n for n in self.nodes if n.id == node_id)


@dataclass
class Compiled:
    """A validated graph: parsed parameters and the topology the executor needs."""

    graph: Graph
    params: dict[NodeId, NodeParams]
    types: dict[NodeId, type[NodeType]]
    upstream: dict[NodeId, list[tuple[NodeId, str, str]]]  # node -> (from, from_port, to_port)
    downstream: dict[NodeId, list[NodeId]]
    triggers: list[NodeId]
    order: list[NodeId]


@dataclass
class GraphValidationError(Exception):
    errors: list[dict[str, Any]] = field(default_factory=list)

    def add(self, path: str, code: str) -> None:
        self.errors.append({"path": path, "code": code})


ReferenceCheck = Callable[[Reference], Awaitable[bool]]


def graph_hash(raw: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _structure(raw: dict[str, Any], errors: GraphValidationError) -> Graph | None:
    try:
        return Graph.model_validate(raw)
    except ValidationError as exc:
        for err in exc.errors():
            errors.add(".".join(str(p) for p in err["loc"]), err["type"])
        return None


def compile_graph(raw: dict[str, Any]) -> Compiled:
    """Parses and checks a graph without permission or reference checks (executor)."""
    errors = GraphValidationError()
    graph = _structure(raw, errors)
    if graph is None:
        raise errors
    compiled = _compile(graph, errors)
    if errors.errors:
        raise errors
    return compiled


def _compile(graph: Graph, errors: GraphValidationError) -> Compiled:
    registry = node_types()
    ids = [n.id for n in graph.nodes]
    if len(set(ids)) != len(ids):
        errors.add("nodes", "duplicate_node_id")
    if len({e.id for e in graph.edges}) != len(graph.edges):
        errors.add("edges", "duplicate_edge_id")
    types, params = _node_types(graph, registry, errors)
    upstream, downstream = _edges(graph, types, errors)

    triggers = [nid for nid, t in types.items() if t.category == NodeCategory.TRIGGER]
    if not triggers:
        errors.add("nodes", "no_trigger")
    order = _topological(ids, upstream, errors)
    reachable = _reachable(triggers, downstream)
    for index, node in enumerate(graph.nodes):
        if node.id in types and node.id not in reachable:
            errors.add(f"nodes.{index}", "unreachable_node")
    for nid, node_type in types.items():
        if node_type.requires_approval_upstream and not _guarded(nid, upstream, types):
            errors.add(f"nodes.{ids.index(nid)}", "approval_required_upstream")
    return Compiled(graph, params, types, dict(upstream), dict(downstream), triggers, order)


def _node_types(
    graph: Graph, registry: Mapping[str, type[NodeType]], errors: GraphValidationError
) -> tuple[dict[NodeId, type[NodeType]], dict[NodeId, NodeParams]]:
    params: dict[NodeId, NodeParams] = {}
    types: dict[NodeId, type[NodeType]] = {}
    for index, node in enumerate(graph.nodes):
        path = f"nodes.{index}"
        node_type = registry.get(node.type)
        if node_type is None or node_type.version != node.type_version:
            errors.add(f"{path}.type", "unknown_node_type")
            continue
        types[node.id] = node_type
        if len(json.dumps(node.params)) > MAX_PARAMS_BYTES:
            errors.add(f"{path}.params", "params_too_large")
            continue
        try:
            params[node.id] = node_type.Params.model_validate(node.params)
        except ValidationError as exc:
            for err in exc.errors():
                errors.add(f"{path}.params." + ".".join(str(p) for p in err["loc"]), err["type"])

    return types, params


def _edges(
    graph: Graph, types: dict[NodeId, type[NodeType]], errors: GraphValidationError
) -> tuple[dict[NodeId, list[tuple[NodeId, str, str]]], dict[NodeId, list[NodeId]]]:
    upstream: dict[NodeId, list[tuple[NodeId, str, str]]] = defaultdict(list)
    downstream: dict[NodeId, list[NodeId]] = defaultdict(list)
    for index, edge in enumerate(graph.edges):
        src, dst = types.get(edge.source.node), types.get(edge.target.node)
        if src is None or dst is None:
            errors.add(f"edges.{index}", "unknown_node")
            continue
        node = graph.node(edge.source.node)
        out_ports = (*src.outputs, *(["error"] if node.settings.on_error == "route" else []))
        if edge.source.port not in out_ports:
            errors.add(f"edges.{index}.from.port", "unknown_port")
        if edge.target.port not in dst.inputs:
            errors.add(f"edges.{index}.to.port", "unknown_port")
        upstream[edge.target.node].append((edge.source.node, edge.source.port, edge.target.port))
        downstream[edge.source.node].append(edge.target.node)
    return upstream, downstream


def _topological(
    ids: list[str], upstream: dict[str, list[tuple[str, str, str]]], errors: GraphValidationError
) -> list[str]:
    incoming = {nid: {src for src, _, _ in upstream.get(nid, [])} for nid in ids}
    ready = deque(nid for nid in ids if not incoming[nid])
    order = []
    while ready:
        current = ready.popleft()
        order.append(current)
        for nid in ids:
            if current in incoming[nid]:
                incoming[nid].discard(current)
                if not incoming[nid]:
                    ready.append(nid)
    if len(order) != len(set(ids)):
        errors.add("edges", "cycle")
    return order


def _reachable(triggers: list[str], downstream: dict[str, list[str]]) -> set[str]:
    seen, stack = set(triggers), list(triggers)
    while stack:
        for nxt in downstream.get(stack.pop(), []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _guarded(
    node: str, upstream: dict[str, list[tuple[str, str, str]]], types: dict[str, type[NodeType]]
) -> bool:
    """Every path from a trigger to ``node`` crosses an approval node."""
    parents = [src for src, _, _ in upstream.get(node, [])]
    if not parents:
        return False
    for parent in parents:
        parent_type = types.get(parent)
        if parent_type is not None and parent_type.type == APPROVAL_TYPE:
            continue
        if parent_type is None or parent_type.category == NodeCategory.TRIGGER:
            return False
        if not _guarded(parent, upstream, types):
            return False
    return True


async def validate_graph(
    raw: dict[str, Any],
    *,
    permissions: frozenset[Permission],
    check_reference: ReferenceCheck,
) -> Compiled:
    """Full validation when saving a version: structure, permissions, references."""
    errors = GraphValidationError()
    graph = _structure(raw, errors)
    if graph is None:
        raise errors
    compiled = _compile(graph, errors)
    for index, node in enumerate(graph.nodes):
        node_type = compiled.types.get(node.id)
        if node_type is None:
            continue
        if not node_type.required_permissions <= permissions:
            errors.add(f"nodes.{index}.type", "permission_required")
        node_params = compiled.params.get(node.id)
        if node_params is None:
            continue
        for reference in node_type().references(node_params):
            if not await check_reference(reference):
                errors.add(f"nodes.{index}.params", f"{reference.kind}_not_found")
    if errors.errors:
        raise errors
    return compiled


def new_graph_id() -> str:
    return uuid.uuid4().hex[:12]
