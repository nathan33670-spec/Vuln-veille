"""Mastodon (spec 07 §2): one instance per connector (e.g. infosec.exchange).

Status search needs an access token on most instances; without one the public
hashtag timeline is read (CVE identifiers are commonly used as hashtags)."""

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
    SecretSlot,
    register,
)
from app.connectors.found import FetchError, Found, as_dict, fetch, from_iso, json_of
from app.core.narrow import expect
from app.watch.feeds import plain_text

_HOST = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class MastodonConfig(ConnectorConfig):
    instance: str = Field(default="infosec.exchange", description="Domaine de l'instance")
    max_results: int = Field(default=20, ge=1, le=40)

    @field_validator("instance")
    @classmethod
    def _host(cls, value: str) -> str:
        value = value.strip().lower().removeprefix("https://").rstrip("/")
        if not _HOST.fullmatch(value):
            raise ValueError("invalid instance domain")
        return value


def hashtag(query: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "", query)[:100]


def _status(status: object) -> Found | None:
    if not isinstance(status, dict) or not isinstance(status.get("url"), str):
        return None
    account = as_dict(status.get("account"))
    text = plain_text(str(status.get("content") or ""))
    return Found(
        source="mastodon",
        url=status["url"],
        title=text[:120],
        content=text,
        author=str(account.get("acct") or "")[:200],
        published_at=from_iso(status.get("created_at")),
        extra={
            "reblogs": status.get("reblogs_count"),
            "favourites": status.get("favourites_count"),
        },
    )


async def search(ctx: ConnectorContext, query: str, limit: int | None = None) -> list[Found]:
    config = expect(ctx.config, MastodonConfig)
    base = f"https://{config.instance}"
    count = str(limit or config.max_results)
    token = ctx.secrets.get("token")
    if token:
        response = await fetch(
            ctx,
            "GET",
            f"{base}/api/v2/search",
            params={"q": query[:200], "type": "statuses", "limit": count, "resolve": "false"},
            headers={"authorization": f"Bearer {token}"},
        )
        data = json_of(response)
        statuses = data.get("statuses") if isinstance(data, dict) else None
    else:
        tag = hashtag(query)
        if not tag:
            return []
        response = await fetch(
            ctx, "GET", f"{base}/api/v1/timelines/tag/{tag}", params={"limit": count}
        )
        statuses = json_of(response)
    if not isinstance(statuses, list):
        raise FetchError("unexpected_answer")
    return [f for f in (_status(s) for s in statuses) if f is not None]


@register
class MastodonConnector(ConnectorType):
    kind = "mastodon"
    family = Family.SOURCE
    label = "Mastodon"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = MastodonConfig
    secret_slots = (SecretSlot("token", "Jeton d'accès en lecture (recherche de posts)", False),)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=30)

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        return (expect(config, MastodonConfig).instance,)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            results = await search(ctx, "CVE", limit=1)
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=True, message=f"{len(results)} post(s) de test")
