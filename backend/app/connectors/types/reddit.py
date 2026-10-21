"""Reddit through the public RSS feeds of chosen subreddits (spec 07 §2). The Data API
is not used (Q31): only the documented public feeds."""

import re

from pydantic import Field, field_validator

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
from app.connectors.found import FetchError, Found, fetch
from app.core.narrow import expect
from app.watch.feeds import FEED_TYPES, FeedError, parse_feed

BASE = "https://www.reddit.com"
_SUB = re.compile(r"^[A-Za-z0-9_]{2,21}$")


class RedditConfig(ConnectorConfig):
    subreddits: list[str] = Field(
        default_factory=lambda: ["netsec", "cybersecurity", "sysadmin"], min_length=1, max_length=20
    )
    max_results: int = Field(default=15, ge=1, le=50)

    @field_validator("subreddits")
    @classmethod
    def _names(cls, value: list[str]) -> list[str]:
        cleaned = [v.strip().removeprefix("r/") for v in value]
        if not all(_SUB.fullmatch(v) for v in cleaned):
            raise ValueError("invalid subreddit name")
        return cleaned


async def search(ctx: ConnectorContext, query: str, limit: int | None = None) -> list[Found]:
    config = expect(ctx.config, RedditConfig)
    found: list[Found] = []
    for sub in config.subreddits:
        response = await fetch(
            ctx,
            "GET",
            f"{BASE}/r/{sub}/search.rss",
            params={
                "q": query[:200],
                "restrict_sr": "on",
                "sort": "new",
                "limit": str(limit or config.max_results),
            },
        )
        try:
            entries = parse_feed(response.content)
        except FeedError as exc:
            raise FetchError(str(exc)) from None
        found.extend(
            Found(
                source="reddit",
                url=e.url,
                title=e.title,
                content=e.content,
                author=e.author,
                published_at=e.published_at,
                extra={"subreddit": sub},
            )
            for e in entries[: limit or config.max_results]
        )
    return found


@register
class RedditConnector(ConnectorType):
    kind = "reddit"
    family = Family.SOURCE
    label = "Reddit (flux RSS publics)"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = RedditConfig
    egress_domains = ("www.reddit.com",)
    content_types = FEED_TYPES
    default_quotas = Quotas(requests_per_minute=10)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        config = expect(ctx.config, RedditConfig)
        try:
            response = await fetch(ctx, "GET", f"{BASE}/r/{config.subreddits[0]}/new/.rss")
            parse_feed(response.content)
        except (FetchError, FeedError) as exc:
            return HealthResult(ok=False, message=str(exc))
        return HealthResult(ok=True, message="flux accessible")
