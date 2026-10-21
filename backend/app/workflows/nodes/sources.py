"""Source nodes (spec 02 §7, queue ``collect``).

Local catalogue sources read the CVE catalogue fed by the global synchronisations.
Remote sources go through a connector selected in their parameters: its egress
policy (domains, size, content types), quotas and secrets apply. Everything read
from outside is stored as an untrusted collected item and flows as data only.
"""

import uuid
from datetime import timedelta
from typing import Any, ClassVar, Literal

from pydantic import Field, HttpUrl

from app.connectors.base import ConnectorContext
from app.connectors.quotas import QuotaExceededError
from app.connectors.types.github import API as GITHUB_API
from app.connectors.types.github import github_headers
from app.connectors.types.http_api import HttpApiConfig, HttpApiConnector, join
from app.net.safe_http import EgressError, SafeResponse
from app.workflows.base import (
    Item,
    NodeCategory,
    NodeContext,
    NodeError,
    NodeParams,
    NodeType,
    Outputs,
    Reference,
    expect,
    item,
    register_node,
)
from app.workflows.expressions import Expr
from app.workflows.feeds import FeedError, parse_feed
from app.workflows.repo import cve_summary

MAX_REMOTE_ITEMS = 200


class SourceNode(NodeType):
    category = NodeCategory.SOURCE
    queue = "collect"
    runs_without_items = True


class RemoteSource(SourceNode):
    uses_egress = True
    connector_kinds: ClassVar[tuple[str, ...]]

    def references(self, params: NodeParams) -> list[Reference]:
        connector_id = getattr(params, "connector_id", None)
        if connector_id is None:
            return []
        return [Reference("connector", connector_id, "source", ",".join(self.connector_kinds))]

    async def fetch(
        self,
        ctx: NodeContext,
        connector: ConnectorContext,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> SafeResponse:
        try:
            if connector.quotas is not None:
                await connector.quotas.consume()
            response = await connector.http.get(url, headers=headers or {}, params=params or {})
        except EgressError as exc:
            raise NodeError(f"egress: {exc.code}") from None
        except QuotaExceededError as exc:
            raise NodeError(f"quota_exceeded: {exc.window}") from None
        if response.status_code != 200:  # noqa: PLR2004
            raise NodeError(f"http_{response.status_code}")
        ctx.log("fetched", bytes=len(response.content))
        return response


# Local catalogue ---------------------------------------------------------------


class NvdParams(NodeParams):
    published_within_hours: int = Field(default=24, ge=1, le=24 * 90)
    min_score: float | None = Field(default=None, ge=0, le=10)
    keyword: str | None = Field(default=None, max_length=100)
    kev_only: bool = False
    limit: int = Field(default=100, ge=1, le=1000)


@register_node
class NvdSource(SourceNode):
    type = "source.nvd"
    label = "Catalogue CVE (NVD)"
    Params = NvdParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, NvdParams)
        records = await ctx.repo.search_cves(
            published_since=ctx.now - timedelta(hours=params.published_within_hours),
            min_score=params.min_score,
            kev_only=params.kev_only,
            kev_added_since=None,
            keyword=params.keyword,
            limit=params.limit,
        )
        return {"out": [item(cve_summary(r), source="catalog.nvd") for r in records]}


class KevParams(NodeParams):
    added_within_days: int = Field(default=7, ge=1, le=365)
    limit: int = Field(default=200, ge=1, le=1000)


@register_node
class KevSource(SourceNode):
    type = "source.cisa_kev"
    label = "Nouvelles entrées KEV (CISA)"
    Params = KevParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, KevParams)
        records = await ctx.repo.search_cves(
            published_since=None,
            min_score=None,
            kev_only=True,
            kev_added_since=ctx.now - timedelta(days=params.added_within_days),
            keyword=None,
            limit=params.limit,
        )
        return {"out": [item(cve_summary(r), source="catalog.kev") for r in records]}


# Remote sources ----------------------------------------------------------------


async def _collected(
    ctx: NodeContext, source_type: str, only_new: bool, **fields: Any
) -> Item | None:
    stored_id, new = await ctx.repo.store_collected(source_type, **fields)
    if only_new and not new:
        return None
    data = {
        "collected_item_id": str(stored_id),
        "url": fields.get("url"),
        "title": fields.get("title") or "",
        "content": (fields.get("content") or "")[:20000],
        "author": fields.get("author") or "",
        "published_at": fields["published_at"].isoformat() if fields.get("published_at") else None,
        "new": new,
    }
    return item(
        data,
        source=source_type,
        trust="untrusted",
        url=fields.get("url"),
        fetched_at=ctx.now.isoformat(),
    )


class RssParams(NodeParams):
    connector_id: uuid.UUID = Field(description="Connecteur RSS de l'espace")
    url: HttpUrl
    max_items: int = Field(default=50, ge=1, le=MAX_REMOTE_ITEMS)
    only_new: bool = Field(default=True, description="Ignorer les entrées déjà collectées")


@register_node
class RssSource(RemoteSource):
    type = "source.rss"
    label = "Flux RSS ou Atom"
    Params = RssParams
    connector_kinds = ("rss",)

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, RssParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        response = await self.fetch(ctx, connector, str(params.url))
        try:
            entries = parse_feed(response.content)
        except FeedError as exc:
            raise NodeError(str(exc)) from None
        out = []
        for entry in entries[: params.max_items]:
            try:
                collected = await _collected(
                    ctx,
                    "rss",
                    params.only_new,
                    url=entry.url,
                    title=entry.title,
                    content=entry.content,
                    author=entry.author,
                    published_at=entry.published_at,
                    source_ref=str(params.url),
                )
            except ValueError:
                continue  # URL refused by the collected-content rules
            if collected is not None:
                out.append(collected)
        ctx.log("feed_parsed", entries=len(entries), emitted=len(out))
        return {"out": out}


class HttpParams(NodeParams):
    connector_id: uuid.UUID = Field(description="Connecteur API HTTP de l'espace")
    path: str = Field(default="", max_length=500, description="Chemin relatif à l'URL de base")
    query: dict[str, str] = Field(default_factory=dict, max_length=20)
    response: Literal["json", "text"] = "json"
    items: Expr | None = Field(default=None, description="Liste d'éléments dans la réponse JSON")
    max_items: int = Field(default=100, ge=1, le=MAX_REMOTE_ITEMS)


@register_node
class HttpSource(RemoteSource):
    type = "source.http"
    label = "Requête HTTP (lecture)"
    Params = HttpParams
    connector_kinds = ("http_api",)

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, HttpParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        config = connector.config
        config = expect(config, HttpApiConfig)
        try:
            url = join(str(config.base_url), params.path)
        except ValueError:
            raise NodeError("invalid_path") from None
        response = await self.fetch(
            ctx, connector, url, headers=HttpApiConnector.headers(connector), params=params.query
        )
        meta = {"url": url, "fetched_at": ctx.now.isoformat()}
        if params.response == "text":
            text = response.content.decode("utf-8", "replace")[:100_000]
            return {"out": [item({"text": text}, source="http", trust="untrusted", **meta)]}
        try:
            body = response.json()
        except ValueError:
            raise NodeError("invalid_json") from None
        values = params.items.evaluate({"json": body}) if params.items else body
        if not isinstance(values, list):
            values = [values]
        out = [
            item(
                v if isinstance(v, dict) else {"value": v}, source="http", trust="untrusted", **meta
            )
            for v in values[: params.max_items]
        ]
        return {"out": out}


class GithubAdvisoriesParams(NodeParams):
    connector_id: uuid.UUID = Field(description="Connecteur GitHub")
    ecosystem: (
        Literal[
            "actions",
            "composer",
            "erlang",
            "go",
            "maven",
            "npm",
            "nuget",
            "other",
            "pip",
            "pub",
            "rubygems",
            "rust",
            "swift",
        ]
        | None
    ) = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    published_within_hours: int = Field(default=24, ge=1, le=24 * 30)
    max_items: int = Field(default=50, ge=1, le=100)
    only_new: bool = True


@register_node
class GithubAdvisoriesSource(RemoteSource):
    type = "source.github_advisories"
    label = "GitHub Security Advisories"
    Params = GithubAdvisoriesParams
    connector_kinds = ("github",)

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, GithubAdvisoriesParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        since = (ctx.now - timedelta(hours=params.published_within_hours)).date().isoformat()
        query = {"type": "reviewed", "per_page": str(params.max_items), "published": f">={since}"}
        if params.ecosystem:
            query["ecosystem"] = params.ecosystem
        if params.severity:
            query["severity"] = params.severity
        response = await self.fetch(
            ctx,
            connector,
            f"{GITHUB_API}/advisories",
            headers=github_headers(connector),
            params=query,
        )
        try:
            advisories = response.json()
        except ValueError:
            raise NodeError("invalid_json") from None
        if not isinstance(advisories, list):
            raise NodeError("unexpected_answer")
        out = []
        for advisory in advisories[: params.max_items]:
            if not isinstance(advisory, dict) or not advisory.get("ghsa_id"):
                continue
            try:
                collected = await _collected(
                    ctx,
                    "github_advisory",
                    params.only_new,
                    url=advisory.get("html_url"),
                    title=f"{advisory.get('ghsa_id')} {advisory.get('summary') or ''}",
                    content=advisory.get("description") or "",
                    published_at=None,
                    source_ref=str(advisory.get("ghsa_id"))[:100],
                )
            except ValueError:
                continue
            if collected is None:
                continue
            collected["json"].update(
                ghsa_id=str(advisory.get("ghsa_id"))[:40],
                cve_id=advisory.get("cve_id") if isinstance(advisory.get("cve_id"), str) else None,
                severity=advisory.get("severity")
                if isinstance(advisory.get("severity"), str)
                else None,
            )
            out.append(collected)
        return {"out": out}
