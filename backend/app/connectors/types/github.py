"""GitHub REST API (advisories now, PoC search in phase 4). A free token is optional;
without it the unauthenticated rate limit applies (60 requests per hour)."""

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

API = "https://api.github.com"


class GithubConfig(ConnectorConfig):
    max_results_per_call: int = Field(default=50, ge=1, le=100)


def github_headers(ctx: ConnectorContext) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.secrets.get("token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


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
