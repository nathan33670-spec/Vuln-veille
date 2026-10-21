"""Workflow engine units: expressions sandbox, graph validation, pure nodes, limits."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.iam.permissions import WORKSPACE_ROLES, Permission
from app.watch.feeds import FeedError, parse_feed
from app.workflows.base import NodeContext, RunInfo, item
from app.workflows.engine import Limits, bound_outputs
from app.workflows.expressions import Expr, ExpressionError, Tpl, compile_template
from app.workflows.graph import GraphValidationError, compile_graph, graph_hash, validate_graph
from app.workflows.nodes.control import If, IfParams
from app.workflows.nodes.transforms import (
    Dedupe,
    DedupeParams,
    ExtractCve,
    ExtractCveParams,
    Filter,
    FilterParams,
    Map,
    MapParams,
    Merge,
    MergeParams,
    find_ids,
)
from app.workflows.nodes.triggers import (
    CveUpdatedParams,
    CveUpdatedTrigger,
    ScheduleParams,
    next_fire,
)
from app.workflows.seeds import SEEDS

ANALYST = WORKSPACE_ROLES["analyst"]


def _edge(i: int, a: str, b: str, port: str = "out", to: str = "in") -> dict[str, Any]:
    return {"id": f"e{i}", "from": {"node": a, "port": port}, "to": {"node": b, "port": to}}


def _graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema_version": 1, "nodes": nodes, "edges": edges}


def _codes(raw: dict[str, Any]) -> set[tuple[str, str]]:
    with pytest.raises(GraphValidationError) as caught:
        compile_graph(raw)
    return {(e["path"], e["code"]) for e in caught.value.errors}


START: dict[str, Any] = {"id": "start", "type": "trigger.manual"}


# Expressions -------------------------------------------------------------------


def test_expressions_select_without_side_effects() -> None:
    expr = Expr.model_validate({"$expr": "length(json.cve_ids) > `0`"})
    assert expr.truthy({"json": {"cve_ids": ["CVE-2026-1"]}})
    assert not expr.truthy({"json": {"cve_ids": []}})
    with pytest.raises(ValueError, match="invalid expression"):
        Expr.model_validate({"$expr": "json.["})


@pytest.mark.parametrize(
    "source",
    [
        "{% include 'x' %}",
        "{% render 'x' %}",
        "{{ x ",
    ],
)
def test_templates_cannot_load_files(source: str) -> None:
    with pytest.raises(ExpressionError):
        compile_template(source)


def test_template_limits_and_data_stays_data() -> None:
    tpl = Tpl.model_validate({"$tpl": "{{ json.title }}"})
    assert tpl.render({"json": {"title": "{{ 7 * 7 }} {% raw %}"}}) == "{{ 7 * 7 }} {% raw %}"
    loop = Tpl.model_validate({"$tpl": "{% for i in (1..100000) %}x{% endfor %}"})
    with pytest.raises(ExpressionError):
        loop.render({})
    assert Tpl.model_validate({"$tpl": "{{ x.__class__ }}"}).render({"x": "s"}) == ""


# Graph validation --------------------------------------------------------------


def test_seed_graphs_are_valid() -> None:
    for _, _, graph in SEEDS.values():
        compiled = compile_graph(graph)
        assert compiled.triggers
        assert graph_hash(graph) == graph_hash(dict(reversed(list(graph.items()))))


def test_graph_structure_rules() -> None:
    limit = {"id": "limit", "type": "transform.limit", "params": {"count": 1}}
    assert ("nodes", "no_trigger") in _codes(_graph([limit], []))
    assert ("edges", "cycle") in _codes(
        _graph(
            [START, limit, {**limit, "id": "other"}],
            [_edge(1, "start", "limit"), _edge(2, "limit", "other"), _edge(3, "other", "limit")],
        )
    )
    codes = _codes(
        _graph(
            [START, limit, {"id": "lost", "type": "transform.limit", "params": {"count": 1}}],
            [_edge(1, "start", "limit", port="nope")],
        )
    )
    assert ("edges.0.from.port", "unknown_port") in codes
    assert ("nodes.2", "unreachable_node") in codes
    assert ("nodes.1.type", "unknown_node_type") in _codes(
        _graph([START, {"id": "x", "type": "code.python"}], [_edge(1, "start", "x")])
    )
    assert ("nodes", "duplicate_node_id") in _codes(_graph([START, START], []))
    codes = _codes(_graph([START, {**limit, "params": {"count": 0}}], [_edge(1, "start", "limit")]))
    assert ("nodes.1.params.count", "greater_than_equal") in codes
    big = {**limit, "params": {"count": 1, "pad": "x" * 70_000}}
    assert ("nodes.1.params", "params_too_large") in _codes(
        _graph([START, big], [_edge(1, "start", "limit")])
    )
    assert any(
        code == "too_long"
        for _, code in _codes(_graph([START] + [{**limit, "id": f"n{i}"} for i in range(200)], []))
    )


def test_error_port_requires_route() -> None:
    nodes: list[dict[str, Any]] = [
        START,
        {"id": "a", "type": "transform.limit", "params": {"count": 1}},
        {"id": "b", "type": "transform.limit", "params": {"count": 1}},
    ]
    edges = [_edge(1, "start", "a"), _edge(2, "a", "b", port="error")]
    assert ("edges.1.from.port", "unknown_port") in _codes(_graph(nodes, edges))
    nodes[1] = {**nodes[1], "settings": {"on_error": "route"}}
    compile_graph(_graph(nodes, edges))


async def test_validation_checks_permissions_and_references() -> None:
    connector = uuid.uuid4()
    rss = {
        "id": "feed",
        "type": "source.rss",
        "params": {"connector_id": str(connector), "url": "https://example.org/feed"},
    }
    graph = _graph([START, rss], [_edge(1, "start", "feed")])
    seen = []

    async def missing(reference: Any) -> bool:
        seen.append(reference)
        return False

    with pytest.raises(GraphValidationError) as caught:
        await validate_graph(graph, permissions=ANALYST, check_reference=missing)
    assert caught.value.errors == [{"path": "nodes.1.params", "code": "connector_not_found"}]
    assert seen[0].id == connector
    assert seen[0].kind_of_connector == "rss"

    async def present(reference: Any) -> bool:
        return True

    await validate_graph(graph, permissions=ANALYST, check_reference=present)


async def test_validation_requires_approval_before_external_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.workflows.base import NodeCategory, NodeType, Outputs, register_node  # noqa: PLC0415

    @register_node
    class Push(NodeType):
        type = "test.push"
        label = "push"
        category = NodeCategory.OUTPUT
        requires_approval_upstream = True
        required_permissions = frozenset({Permission.CONNECTOR_PUBLISH_PUSH})

        async def execute(self, ctx: NodeContext, params: Any, inputs: Outputs) -> Outputs:
            return {}

    direct = _graph([START, {"id": "push", "type": "test.push"}], [_edge(1, "start", "push")])
    assert ("nodes.1", "approval_required_upstream") in _codes(direct)
    guarded = _graph(
        [START, {"id": "ok", "type": "control.approval"}, {"id": "push", "type": "test.push"}],
        [_edge(1, "start", "ok"), _edge(2, "ok", "push", port="approved")],
    )
    compile_graph(guarded)

    async def present(reference: Any) -> bool:
        return True

    with pytest.raises(GraphValidationError) as caught:
        await validate_graph(
            guarded, permissions=WORKSPACE_ROLES["viewer"], check_reference=present
        )
    assert {"path": "nodes.2.type", "code": "permission_required"} in caught.value.errors


# Nodes -------------------------------------------------------------------------


class _Repo:
    def __init__(self) -> None:
        self.keys: set[tuple[str, str]] = set()

    async def remember(self, namespace: str, key: str, days: int) -> bool:
        if (namespace, key) in self.keys:
            return False
        self.keys.add((namespace, key))
        return True


def _ctx(repo: Any = None) -> NodeContext:
    return NodeContext(
        workspace_id=uuid.uuid4(),
        run=RunInfo(uuid.uuid4(), uuid.uuid4(), "manual", {"k": 1}, "wf"),
        node_id="n",
        now=datetime.now(UTC),
        repo=repo or _Repo(),  # type: ignore[arg-type]
        connectors=None,  # type: ignore[arg-type]
    )


def _items(*values: dict[str, Any]) -> list[dict[str, Any]]:
    return [item(v, source="test") for v in values]


async def test_transform_nodes() -> None:
    ctx = _ctx()
    entries = _items(
        {"score": 9.8, "url": "u1"}, {"score": 4.0, "url": "u1"}, {"score": 7.5, "url": "u2"}
    )
    kept = await Filter().execute(
        ctx,
        FilterParams.model_validate({"condition": {"$expr": "json.score >= `7`"}}),
        {"in": entries},
    )
    assert [i["json"]["score"] for i in kept["out"]] == [9.8, 7.5]

    mapped = await Map().execute(
        ctx,
        MapParams.model_validate(
            {
                "fields": {
                    "high": {"$expr": "json.score > `9`"},
                    "label": {"$tpl": "S={{ json.score }}"},
                    "fixed": 1,
                }
            }
        ),
        {"in": entries[:1]},
    )
    assert mapped["out"][0]["json"] == {
        "score": 9.8,
        "url": "u1",
        "high": True,
        "label": "S=9.8",
        "fixed": 1,
    }

    deduped = await Dedupe().execute(
        ctx, DedupeParams.model_validate({"key": {"$expr": "json.url"}}), {"in": entries}
    )
    assert [i["json"]["url"] for i in deduped["out"]] == ["u1", "u2"]
    again = await Dedupe().execute(
        ctx, DedupeParams.model_validate({"key": {"$expr": "json.url"}}), {"in": entries}
    )
    assert again["out"] == []  # remembered between runs

    branches = await If().execute(
        ctx, IfParams.model_validate({"condition": {"$expr": "json.score > `5`"}}), {"in": entries}
    )
    assert (len(branches["true"]), len(branches["false"])) == (2, 1)

    joined = await Merge().execute(
        ctx,
        MergeParams.model_validate({"mode": "join", "key": {"$expr": "json.url"}}),
        {"in": _items({"url": "u1", "a": 1}), "in2": _items({"url": "u1", "b": 2}, {"url": "u3"})},
    )
    assert joined["out"][0]["json"] == {"url": "u1", "a": 1, "b": 2}


async def test_extract_cve_and_ghsa() -> None:
    assert find_ids("cve-2026-12345 and GHSA-abcd-efgh-2345, CVE-2026-12345") == (
        ["CVE-2026-12345"],
        [],  # 'a', 'b', 'e' are not in the GHSA alphabet
    )
    assert find_ids("GHSA-jfh8-c2jp-5v3q")[1] == ["GHSA-jfh8-c2jp-5v3q"]
    out = await ExtractCve().execute(
        _ctx(),
        ExtractCveParams(),
        {"in": _items({"title": "Avis CVE-2026-0001", "content": ""}, {"title": "rien"})},
    )
    assert [i["json"]["cve_ids"] for i in out["out"]] == [["CVE-2026-0001"]]


def test_triggers() -> None:
    with pytest.raises(ValueError, match="at most one run every 5 minutes"):
        ScheduleParams(cron="* * * * *")
    with pytest.raises(ValueError, match="unknown time zone"):
        ScheduleParams(cron="0 7 * * *", timezone="Mars/Olympus")
    after = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    assert next_fire("0 7 * * *", "Europe/Paris", after) == datetime(2026, 7, 2, 5, 0, tzinfo=UTC)
    trigger = CveUpdatedTrigger()
    params = CveUpdatedParams.model_validate(
        {"change_types": ["kev_added"], "filter": {"$expr": "json.severity == 'CRITICAL'"}}
    )
    assert trigger.accepts(params, {"change_types": ["kev_added"], "severity": "CRITICAL"})
    assert not trigger.accepts(params, {"change_types": ["kev_added"], "severity": "LOW"})
    assert not trigger.accepts(params, {"change_types": ["cpe_added"], "severity": "CRITICAL"})


def test_feed_parser_refuses_entities() -> None:
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
        b"<rss><channel><item><title>&a;</title></item></channel></rss>"
    )
    with pytest.raises(FeedError):
        parse_feed(bomb)
    with pytest.raises(FeedError):
        parse_feed(b"<html/>")
    rss = (
        b"<rss><channel><item><title>T &amp;lt;b&amp;gt;</title><link>javascript:alert(1)</link>"
        b"<description>&lt;script&gt;x&lt;/script&gt;Texte</description></item></channel></rss>"
    )
    (entry,) = parse_feed(rss)
    assert entry.url is None
    assert "<" not in entry.content


def test_bound_outputs() -> None:
    limits = Limits(max_items_per_output=2, max_item_bytes=200, max_output_bytes=10_000)
    outputs: dict[str, Any] = {
        "out": [
            *_items({"a": 1}, {"a": 2}, {"a": 3}),
            "not an item",
            item({"big": "x" * 500}, source="t"),
        ],
        "undeclared": _items({"a": 4}),
    }
    bounded, count, truncated = bound_outputs(outputs, ("out",), limits)
    assert count == 2
    assert truncated
    assert set(bounded) == {"out"}
    when = datetime(2026, 1, 1, tzinfo=UTC)
    bounded, _, _ = bound_outputs({"out": [item({"at": when}, source="t")]}, ("out",))
    assert bounded["out"][0]["json"]["at"] == str(when)
