"""GitHub REST API (advisories now, PoC search in phase 4). A free token is optional;
without it the unauthenticated rate limit applies (60 requests per hour)."""

from typing import Any, Literal, get_args

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
from app.connectors.found import Found, as_dict, fetch, json_of

API = "https://api.github.com"


class GithubConfig(ConnectorConfig):
    max_results_per_call: int = Field(default=50, ge=1, le=100)


def github_headers(ctx: ConnectorContext) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.secrets.get("token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


SearchKind = Literal["repositories", "code", "commits", "issues"]
SEARCH_KINDS: tuple[str, ...] = get_args(SearchKind)


def _found(kind: str, entry: dict[str, Any]) -> Found | None:
    url = entry.get("html_url")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        return None
    repo = as_dict(entry.get("repository"))
    if kind == "repositories":
        owner = as_dict(entry.get("owner"))
        return Found(
            source="github",
            url=url,
            title=str(entry.get("full_name") or ""),
            content=str(entry.get("description") or ""),
            author=str(owner.get("login") or ""),
            extra={
                "stars": entry.get("stargazers_count"),
                "forks": entry.get("forks_count"),
                "fork": entry.get("fork"),
                "archived": entry.get("archived"),
                "created_at": entry.get("created_at"),
                "pushed_at": entry.get("pushed_at"),
            },
        )
    if kind == "code":
        return Found(
            source="github",
            url=url,
            title=f"{repo.get('full_name', '')}:{entry.get('path', '')}",
            content="",
        )
    if kind == "commits":
        commit = as_dict(entry.get("commit"))
        return Found(
            source="github",
            url=url,
            title=str(repo.get("full_name") or ""),
            content=str(commit.get("message") or "")[:2000],
        )
    return Found(
        source="github",
        url=url,
        title=str(entry.get("title") or ""),
        content=str(entry.get("body") or "")[:2000],
        extra={"state": entry.get("state")},
    )


async def search(ctx: ConnectorContext, kind: str, query: str, limit: int) -> list[Found]:
    """Repositories, code, commits or issues mentioning ``query`` (e.g. a CVE: PoCs)."""
    if kind not in SEARCH_KINDS:
        raise ValueError("unknown search kind")
    response = await fetch(
        ctx,
        "GET",
        f"{API}/search/{kind}",
        headers=github_headers(ctx),
        params={"q": query[:256], "per_page": str(min(limit, 100))},
    )
    items = as_dict(json_of(response)).get("items")
    found = (_found(kind, as_dict(e)) for e in (items if isinstance(items, list) else []))
    return [f for f in found if f is not None]


@register
class GithubConnector(ConnectorType):
    kind = "github"
    family = Family.SOURCE
    label = "GitHub (API REST)"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE_ACCOUNT
    config_model = GithubConfig
    secret_slots = (SecretSlot("token", "Jeton d'accès personnel (lecture seule)", False),)
    egress_domains = ("api.github.com",)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=30)
    max_response_bytes = 5 * 1024 * 1024

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        response = await ctx.http.get(f"{API}/rate_limit", headers=github_headers(ctx))
        if response.status_code != 200:  # noqa: PLR2004
            return HealthResult(ok=False, message=f"http_{response.status_code}")
        remaining = response.json().get("resources", {}).get("core", {}).get("remaining")
        return HealthResult(ok=True, message=f"requêtes restantes : {remaining}")
