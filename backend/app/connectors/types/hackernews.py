"""Hacker News through the free Algolia search API (spec 07 §2)."""

from typing import Literal

from pydantic import Field

from app.connectors.base import (
    ConnectorConfig,
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    Quotas,
    Scope,
    register,
)
from app.connectors.found import FetchError, Found, fetch, from_iso, json_of
from app.core.narrow import expect
from app.watch.feeds import plain_text

API = "https://hn.algolia.com/api/v1/search_by_date"
ITEM = "https://news.ycombinator.com/item?id={}"


class HackerNewsConfig(ConnectorConfig):
    include: Literal["story", "comment", "both"] = "both"
    max_results: int = Field(default=20, ge=1, le=100)


async def search(ctx: ConnectorContext, query: str, limit: int | None = None) -> list[Found]:
    config = expect(ctx.config, HackerNewsConfig)
    tags = "(story,comment)" if config.include == "both" else config.include
    response = await fetch(
        ctx,
        "GET",
        API,
        params={
            "query": query[:200],
            "tags": tags,
            "hitsPerPage": str(limit or config.max_results),
        },
    )
    data = json_of(response)
    hits = data.get("hits") if isinstance(data, dict) else None
    if not isinstance(hits, list):
        raise FetchError("unexpected_answer")
    found = []
    for hit in hits:
        if not isinstance(hit, dict) or not hit.get("objectID"):
            continue
        text = plain_text(str(hit.get("comment_text") or hit.get("story_text") or ""))
        title = str(hit.get("title") or hit.get("story_title") or "")
        found.append(
            Found(
                source="hackernews",
                url=ITEM.format(int(hit["objectID"])) if str(hit["objectID"]).isdigit() else None,
                title=title,
                content=text,
                author=str(hit.get("author") or "")[:200],
                published_at=from_iso(hit.get("created_at")),
                extra={"link": hit.get("url"), "points": hit.get("points")},
            )
        )
    return found


@register
class HackerNewsConnector(ConnectorType):
    kind = "hackernews"
    family = Family.SOURCE
    label = "Hacker News (API Algolia)"
    scopes = frozenset({Scope.GLOBAL, Scope.WORKSPACE})
    cost_class = CostClass.FREE
    config_model = HackerNewsConfig
    egress_domains = ("hn.algolia.com",)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=30)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            results = await search(ctx, "CVE", limit=1)
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=True, message=f"{len(results)} résultat(s) de test")
