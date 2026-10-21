"""Watch sources on the free connectors (spec 02 §7, queue ``collect``, plan 4.13).

They search for what an item is about (by default its CVE): one search per input item,
or a single one when the node starts a run on a schedule. Results are stored as
untrusted collected items and carry the item's ``cve_id`` and ``vulnerability_id`` on,
so ``vuln.upsert`` can attach them as evidence.
"""

import uuid
from collections.abc import Awaitable, Callable
from typing import ClassVar

from pydantic import Field

from app.connectors.base import ConnectorConfig, ConnectorContext
from app.connectors.found import FetchError, Found
from app.connectors.types import bluesky, github, hackernews, mastodon, reddit, stackexchange
from app.connectors.types.x_reader import XReaderConfig, discover_post_urls, read_post
from app.core.narrow import expect
from app.workflows.base import Item, NodeContext, NodeError, NodeParams, Outputs, register_node
from app.workflows.expressions import Tpl
from app.workflows.nodes.sources import RemoteSource, collect_item

MAX_QUERIES = 20
CARRIED = ("cve_id", "vulnerability_id", "ref")
Search = Callable[[ConnectorContext, str, int], Awaitable[list[Found]]]


def _cve_query() -> Tpl:
    return Tpl.model_validate({"$tpl": "{{ json.cve_id }}"})


class SearchParams(NodeParams):
    connector_id: uuid.UUID
    query: Tpl = Field(
        default_factory=_cve_query, description="Requête, par défaut la CVE de l'élément"
    )
    max_results: int = Field(default=10, ge=1, le=50, description="Résultats par recherche")
    only_new: bool = Field(default=False, description="Ignorer les éléments déjà collectés")


async def _emit(
    ctx: NodeContext, found: list[Found], origin: Item | None, only_new: bool, query: str
) -> list[Item]:
    carried = {k: v for k, v in (origin or {}).get("json", {}).items() if k in CARRIED}
    out = []
    for entry in found:
        try:
            stored = await collect_item(
                ctx,
                entry.source,
                only_new,
                url=entry.url,
                title=entry.title,
                content=entry.content,
                author=entry.author,
                published_at=entry.published_at,
                source_ref=query[:500],
            )
        except ValueError:
            continue  # URL refused by the collected-content rules
        if stored is not None:
            stored["json"].update(carried, query=query)
            out.append(stored)
    return out


class WatchSearch(RemoteSource):
    async def searches(
        self,
        ctx: NodeContext,
        params: SearchParams,
        inputs: Outputs,
        connector: ConnectorContext,
        search: Search,
    ) -> Outputs:
        entries: list[Item | None] = list(inputs.get("in", [])[:MAX_QUERIES]) or [None]
        out: list[Item] = []
        seen: set[str] = set()
        for entry in entries:
            query = " ".join(params.query.render(ctx.expression_context(entry)).split())[:256]
            if not query or query in seen:
                continue
            seen.add(query)
            try:
                found = await search(connector, query, params.max_results)
            except FetchError as exc:
                raise NodeError(exc.code) from None
            out.extend(await _emit(ctx, found, entry, params.only_new, query))
        ctx.log("searched", queries=len(seen), emitted=len(out))
        return {"out": out}


class GithubSearchParams(SearchParams):
    kind: github.SearchKind = "repositories"


@register_node
class GithubSearchSource(WatchSearch):
    type = "source.github_search"
    label = "GitHub : dépôts, code, commits (PoC)"
    Params = GithubSearchParams
    connector_kinds = ("github",)

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, GithubSearchParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        kind = params.kind

        async def search(target: ConnectorContext, query: str, limit: int) -> list[Found]:
            return await github.search(target, kind, query, limit)

        return await self.searches(ctx, params, inputs, connector, search)


@register_node
class StackExchangeSource(WatchSearch):
    type = "source.stackexchange"
    label = "Stack Overflow et Stack Exchange"
    Params = SearchParams
    connector_kinds = ("stackexchange",)

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, SearchParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        return await self.searches(ctx, params, inputs, connector, stackexchange.search)


SOCIAL: dict[type[ConnectorConfig], tuple[str, Search]] = {
    mastodon.MastodonConfig: ("mastodon", mastodon.search),
    bluesky.BlueskyConfig: ("bluesky", bluesky.search),
    reddit.RedditConfig: ("reddit", reddit.search),
    hackernews.HackerNewsConfig: ("hackernews", hackernews.search),
}


@register_node
class SocialSource(WatchSearch):
    type = "source.social"
    label = "Réseaux et forums (Mastodon, Bluesky, Reddit, Hacker News)"
    Params = SearchParams
    connector_kinds = tuple(kind for kind, _ in SOCIAL.values())

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, SearchParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        _, search = SOCIAL[type(connector.config)]
        return await self.searches(ctx, params, inputs, connector, search)


class XParams(NodeParams):
    connector_id: uuid.UUID
    max_items: int = Field(default=20, ge=1, le=100, description="Éléments examinés")
    only_new: bool = False


@register_node
class XSource(RemoteSource):
    """Free reading of X (spec 07 §2.1): post URLs cited by the input items (layer 1),
    then their text through the official oEmbed endpoint. No paid API, no scraping."""

    type = "source.x"
    label = "X : posts cités, lus par l'oEmbed officiel"
    Params = XParams
    connector_kinds = ("x_reader",)
    runs_without_items: ClassVar[bool] = False

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, XParams)
        connector = await ctx.connectors.open(params.connector_id, self.connector_kinds)
        reads = expect(connector.config, XReaderConfig).max_reads_per_cve
        out: list[Item] = []
        withdrawn = 0
        for entry in inputs.get("in", [])[: params.max_items]:
            data = entry.get("json", {})
            text = "\n".join(str(data.get(k) or "") for k in ("url", "title", "content"))
            for url in discover_post_urls(text)[:reads]:
                try:
                    post = await read_post(connector, url)
                except FetchError as exc:
                    raise NodeError(exc.code) from None
                if post is None:
                    withdrawn += 1
                    continue
                out.extend(await _emit(ctx, [post], entry, params.only_new, url))
        ctx.log("x_read", emitted=len(out), withdrawn=withdrawn)
        return {"out": out}
