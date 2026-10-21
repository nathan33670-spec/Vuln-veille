"""Stack Overflow and Security StackExchange through the free API (spec 07 §2).
Without a key the daily quota is small; a free key raises it (secret slot)."""

import html
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
    SecretSlot,
    register,
)
from app.connectors.found import FetchError, Found, as_dict, fetch, from_timestamp, json_of
from app.core.narrow import expect

API = "https://api.stackexchange.com/2.3"
Site = Literal["stackoverflow", "security", "serverfault", "superuser", "askubuntu"]
DEFAULT_SITES: tuple[Site, ...] = ("stackoverflow", "security")


class StackExchangeConfig(ConnectorConfig):
    sites: list[Site] = Field(default_factory=lambda: list(DEFAULT_SITES), min_length=1)
    max_results: int = Field(default=10, ge=1, le=50)


async def search(ctx: ConnectorContext, query: str, limit: int | None = None) -> list[Found]:
    config = expect(ctx.config, StackExchangeConfig)
    found: list[Found] = []
    for site in config.sites:
        params = {
            "q": query[:200],
            "site": site,
            "order": "desc",
            "sort": "relevance",
            "pagesize": str(limit or config.max_results),
        }
        if ctx.secrets.get("key"):
            params["key"] = ctx.secrets["key"]
        data = json_of(await fetch(ctx, "GET", f"{API}/search/advanced", params=params))
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            raise FetchError("unexpected_answer")
        for item in data["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("link"), str):
                continue
            owner = as_dict(item.get("owner"))
            found.append(
                Found(
                    source="stackexchange",
                    url=item["link"],
                    title=html.unescape(str(item.get("title") or "")),
                    content=", ".join(str(t) for t in item.get("tags") or [])[:500],
                    author=html.unescape(str(owner.get("display_name") or "")),
                    published_at=from_timestamp(item.get("creation_date")),
                    extra={
                        "site": site,
                        "score": item.get("score"),
                        "answered": bool(item.get("is_answered")),
                        "answers": item.get("answer_count"),
                    },
                )
            )
    return found


@register
class StackExchangeConnector(ConnectorType):
    kind = "stackexchange"
    family = Family.SOURCE
    label = "Stack Exchange (Stack Overflow, Security)"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE_ACCOUNT
    config_model = StackExchangeConfig
    secret_slots = (SecretSlot("key", "Clé d'application gratuite (quota relevé)", False),)
    egress_domains = ("api.stackexchange.com",)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=20, requests_per_day=250)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            results = await search(ctx, "CVE-2021-44228", limit=1)
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=True, message=f"{len(results)} résultat(s) de test")
