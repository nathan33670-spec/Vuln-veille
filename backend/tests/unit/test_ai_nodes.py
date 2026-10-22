"""AI nodes, watch source nodes and the investigation seeds (plan 4.12-4.14)."""

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, get_args

import httpx
import pytest
from pydantic import ValidationError

from app.ai.agents.invoke import AgentNotFoundError, AgentResult
from app.ai.agents.presets import PRESETS
from app.ai.agents.spec import AgentSpec
from app.connectors.base import ConnectorConfig, ConnectorContext, registered
from app.connectors.types.github import GithubConfig
from app.connectors.types.hackernews import HackerNewsConfig
from app.connectors.types.x_reader import OEMBED, XReaderConfig
from app.workflows.base import NodeContext, NodeError, RunInfo, item, node_types
from app.workflows.graph import compile_graph
from app.workflows.nodes.ai import (
    AgentNode,
    AgentParams,
    Classify,
    ClassifyParams,
    ExtractParams,
    PresetKey,
    Relevance,
    RelevanceParams,
)
from app.workflows.nodes.watch import (
    GithubSearchParams,
    GithubSearchSource,
    SearchParams,
    SocialSource,
    XParams,
    XSource,
)
from app.workflows.seeds import SEEDS
from tests.web_fakes import FakeWeb


class _Agents:
    def __init__(self, missing: bool = False) -> None:
        self.calls: list[tuple[str, Any, dict[str, Any]]] = []
        self.missing = missing

    async def run_agent(
        self, agent_id: uuid.UUID | None, preset: str | None, payload: dict[str, Any], ctx: str
    ) -> AgentResult:
        if self.missing:
            raise AgentNotFoundError("agent_not_found")
        self.calls.append(("agent", preset or agent_id, payload))
        return AgentResult(
            status="succeeded",
            run_id=uuid.uuid4(),
            output={"relevant": True},
            cost_usd=Decimal("0.01"),
        )

    async def run_task(
        self, task: str, spec: AgentSpec, payload: dict[str, Any], ctx: str
    ) -> AgentResult:
        self.calls.append((task, spec, payload))
        return AgentResult(status="refused", run_id=uuid.uuid4(), error="refusal")


class _Tech:
    display_name = "Apache Log4j"


class _Repo:
    def __init__(self) -> None:
        self.stored: list[dict[str, Any]] = []

    async def scope(self) -> tuple[None, list[_Tech]]:
        return None, [_Tech()]

    async def store_collected(self, source_type: str, **fields: Any) -> tuple[uuid.UUID, bool]:
        self.stored.append({"source_type": source_type, **fields})
        return uuid.uuid4(), True


class _Connectors:
    def __init__(self, web: FakeWeb, config: ConnectorConfig) -> None:
        self.web, self.config = web, config

    async def open(self, connector_id: uuid.UUID, kinds: tuple[str, ...]) -> ConnectorContext:
        type_ = next(t for t in registered().values() if isinstance(self.config, t.config_model))
        assert type_.kind in kinds
        return ConnectorContext(
            connector_id=connector_id,
            workspace_id=None,
            config=self.config,
            secrets={},
            http=self.web.client(*type_.egress_for(self.config)),
        )


def _ctx(agents: Any = None, connectors: Any = None, repo: Any = None) -> NodeContext:
    return NodeContext(
        workspace_id=uuid.uuid4(),
        run=RunInfo(uuid.uuid4(), uuid.uuid4(), "manual", {}, "wf"),
        node_id="n",
        now=datetime.now(UTC),
        repo=repo or _Repo(),  # type: ignore[arg-type]
        connectors=connectors,
        agents=agents,
        node_run_id=uuid.uuid4(),
    )


CVE_ITEM = item({"cve_id": "CVE-2026-1234", "vulnerability_id": "v-1", "cve": {"x": 1}}, source="t")


# Presets and seeds -------------------------------------------------------------------


def test_presets_match_the_node_choices_and_validate() -> None:
    assert set(get_args(PresetKey)) == set(PRESETS)
    for preset in PRESETS.values():
        spec = AgentSpec.model_validate(preset.spec)
        assert spec.output_schema is not None
        assert spec.engine_mode == "inherit"  # the space's preferred engine
    assert PRESETS["synthesis"].spec["tools"] == []  # works on the others' outputs only


def test_seeds_compile_and_use_known_presets() -> None:
    types = node_types()
    for _, _, graph in SEEDS.values():
        compile_graph(graph)
        for node in graph["nodes"]:
            assert node["type"] in types
            if node["type"] == "ai.agent":
                assert node["params"]["preset"] in PRESETS
                assert node["params"]["output_key"] == node["id"]


# AI nodes ----------------------------------------------------------------------------


async def test_agent_node_passes_validated_output_under_its_key() -> None:
    agents = _Agents()
    params = AgentParams.model_validate(
        {"preset": "triage", "output_key": "triage", "input": {"$expr": "{cve_id: json.cve_id}"}}
    )
    out = await AgentNode().execute(_ctx(agents), params, {"in": [CVE_ITEM]})
    entry = out["out"][0]["json"]
    assert entry["cve_id"] == "CVE-2026-1234"
    assert entry["triage"]["status"] == "succeeded"
    assert entry["triage"]["output"] == {"relevant": True}
    assert entry["triage"]["cost_usd"] == "0.01"
    assert agents.calls == [("agent", "triage", {"cve_id": "CVE-2026-1234"})]


async def test_agent_node_errors() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        AgentParams.model_validate({"preset": "triage", "agent_id": str(uuid.uuid4())})
    with pytest.raises(ValidationError):
        AgentParams.model_validate({"preset": "shell"})
    params = AgentParams.model_validate({"preset": "triage"})
    with pytest.raises(NodeError, match="agent_not_found"):
        await AgentNode().execute(_ctx(_Agents(missing=True)), params, {"in": [CVE_ITEM]})
    with pytest.raises(NodeError, match="agents_unavailable"):
        await AgentNode().execute(_ctx(None), params, {"in": [CVE_ITEM]})
    agent_id = uuid.uuid4()
    refs = AgentNode().references(AgentParams.model_validate({"agent_id": str(agent_id)}))
    assert [(r.kind, r.id) for r in refs] == [("agent", agent_id)]


async def test_agent_node_caps_the_items_it_sends() -> None:
    agents = _Agents()
    params = AgentParams.model_validate({"preset": "poc_hunter", "max_items": 2})
    ctx = _ctx(agents)
    out = await AgentNode().execute(ctx, params, {"in": [CVE_ITEM] * 5})
    assert len(out["out"]) == 2
    assert ctx.logs[0]["message"] == "items_capped"


async def test_classify_builds_a_closed_schema_and_reports_refusals() -> None:
    agents = _Agents()
    params = ClassifyParams.model_validate(
        {"labels": ["poc", "patch", "poc", " discussion "], "output_key": "kind"}
    )
    assert params.labels == ["poc", "patch", "discussion"]
    out = await Classify().execute(_ctx(agents), params, {"in": [CVE_ITEM]})
    assert out["out"][0]["json"]["kind"]["status"] == "refused"
    task, spec, _ = agents.calls[0]
    assert task == "ai.classify"
    assert spec.output_schema["properties"]["label"]["enum"] == ["poc", "patch", "discussion"]
    assert spec.tools == []
    assert spec.limits.max_tool_calls == 0
    with pytest.raises(ValidationError):
        ClassifyParams.model_validate({"labels": ["only"]})


def test_extract_schema_follows_agent_rules() -> None:
    with pytest.raises(ValidationError, match="describe an object"):
        ExtractParams.model_validate({"output_schema": {"type": "string"}})
    ok = ExtractParams.model_validate(
        {"output_schema": {"type": "object", "properties": {"version": {"type": "string"}}}}
    )
    assert ok.output_key == "extracted"


async def test_relevance_profile_from_the_watch_scope() -> None:
    agents = _Agents()
    await Relevance().execute(_ctx(agents), RelevanceParams(), {"in": [CVE_ITEM]})
    _, spec, _ = agents.calls[0]
    assert "Apache Log4j" in spec.system_prompt
    with pytest.raises(ValidationError, match="profile_text"):
        RelevanceParams.model_validate({"profile": "text"})


# Watch sources -----------------------------------------------------------------------


async def test_github_search_source_runs_one_search_per_cve_and_carries_it() -> None:
    web = FakeWeb()
    queries: list[str] = []

    def search(request: httpx.Request) -> tuple[int, Any]:
        queries.append(request.url.params["q"])
        return 200, {
            "items": [
                {"full_name": "a/poc", "html_url": "https://github.com/a/poc", "description": "x"},
                {"full_name": "evil", "html_url": "https://evil.example/x"},  # not GitHub
            ]
        }

    web.routes["https://api.github.com/search/repositories"] = search
    repo = _Repo()
    ctx = _ctx(connectors=_Connectors(web, GithubConfig()), repo=repo)
    params = GithubSearchParams.model_validate({"connector_id": str(uuid.uuid4())})
    out = await GithubSearchSource().execute(ctx, params, {"in": [CVE_ITEM, CVE_ITEM]})
    assert queries == ["CVE-2026-1234"]  # the same query once
    assert [i["json"]["url"] for i in out["out"]] == ["https://github.com/a/poc"]
    entry = out["out"][0]
    assert entry["json"]["cve_id"] == "CVE-2026-1234"
    assert entry["json"]["vulnerability_id"] == "v-1"
    assert "cve" not in entry["json"]  # only identifiers are carried on
    assert entry["meta"]["trust"] == "untrusted"
    assert repo.stored[0]["source_type"] == "github"


async def test_social_source_uses_the_connector_kind() -> None:
    web = FakeWeb()
    web.json(
        "https://hn.algolia.com/api/v1/search_by_date",
        {"hits": [{"objectID": "7", "title": "CVE-2026-1234 exploited", "author": "hn"}]},
    )
    ctx = _ctx(connectors=_Connectors(web, HackerNewsConfig()))
    params = SearchParams.model_validate({"connector_id": str(uuid.uuid4())})
    out = await SocialSource().execute(ctx, params, {"in": [CVE_ITEM]})
    assert [i["json"]["url"] for i in out["out"]] == ["https://news.ycombinator.com/item?id=7"]


async def test_x_source_reads_the_posts_cited_by_items() -> None:
    web = FakeWeb()

    def oembed(request: httpx.Request) -> tuple[int, Any]:
        if request.url.params["url"].endswith("2"):
            return 404, {}
        return 200, {"author_url": "https://twitter.com/r", "html": "<p>exploited in the wild</p>"}

    web.routes[OEMBED] = oembed
    cited = item(
        {
            "cve_id": "CVE-2026-1234",
            "content": "see https://x.com/r/status/100001 and https://twitter.com/s/status/100002",
        },
        source="rss",
    )
    ctx = _ctx(connectors=_Connectors(web, XReaderConfig()))
    params = XParams.model_validate({"connector_id": str(uuid.uuid4())})
    out = await XSource().execute(ctx, params, {"in": [cited]})
    assert [i["json"]["url"] for i in out["out"]] == ["https://x.com/r/status/100001"]
    assert out["out"][0]["json"]["content"] == "exploited in the wild"
    assert ctx.logs[-1]["withdrawn"] == 1


async def test_agent_node_condition_lets_other_items_pass_without_a_run() -> None:
    agents = _Agents()
    params = AgentParams.model_validate(
        {"preset": "social", "output_key": "social", "run_if": {"$expr": "json.kev"}}
    )
    kev = item({"cve_id": "CVE-2026-1", "kev": True}, source="t")
    other = item({"cve_id": "CVE-2026-2", "kev": False}, source="t")
    out = await AgentNode().execute(_ctx(agents), params, {"in": [kev, other]})
    assert [i["json"]["social"]["status"] for i in out["out"]] == ["succeeded", "skipped"]
    assert out["out"][1]["json"]["social"]["error"] == "condition_not_met"
    assert len(agents.calls) == 1  # no engine call for the second item
