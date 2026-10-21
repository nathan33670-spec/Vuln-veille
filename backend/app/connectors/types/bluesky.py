"""Bluesky (spec 07 §2): post search needs a session, opened with a free account's
app password (never the account password)."""

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
from app.connectors.found import FetchError, Found, as_dict, fetch, from_iso, json_of
from app.core.narrow import expect

PDS = "https://bsky.social/xrpc"


class BlueskyConfig(ConnectorConfig):
    handle: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,252}$", description="Identifiant du compte")
    max_results: int = Field(default=25, ge=1, le=100)


async def _session(ctx: ConnectorContext) -> str:
    config = expect(ctx.config, BlueskyConfig)
    response = await fetch(
        ctx,
        "POST",
        f"{PDS}/com.atproto.server.createSession",
        json_body={"identifier": config.handle, "password": ctx.secrets["app_password"]},
    )
    data = json_of(response)
    token = data.get("accessJwt") if isinstance(data, dict) else None
    if not isinstance(token, str):
        raise FetchError("no_session")
    return token


def _post(post: object) -> Found | None:
    if not isinstance(post, dict):
        return None
    uri = str(post.get("uri") or "")
    author = as_dict(post.get("author"))
    record = as_dict(post.get("record"))
    handle = str(author.get("handle") or "")
    rkey = uri.rsplit("/", 1)[-1] if uri.startswith("at://") else ""
    if not handle or not rkey:
        return None
    text = str(record.get("text") or "")
    return Found(
        source="bluesky",
        url=f"https://bsky.app/profile/{handle}/post/{rkey}",
        title=text[:120],
        content=text,
        author=handle[:200],
        published_at=from_iso(record.get("createdAt")),
        extra={"likes": post.get("likeCount"), "reposts": post.get("repostCount")},
    )


async def search(ctx: ConnectorContext, query: str, limit: int | None = None) -> list[Found]:
    config = expect(ctx.config, BlueskyConfig)
    token = await _session(ctx)
    response = await fetch(
        ctx,
        "GET",
        f"{PDS}/app.bsky.feed.searchPosts",
        params={"q": query[:200], "limit": str(limit or config.max_results), "sort": "latest"},
        headers={"authorization": f"Bearer {token}"},
    )
    data = json_of(response)
    posts = data.get("posts") if isinstance(data, dict) else None
    if not isinstance(posts, list):
        raise FetchError("unexpected_answer")
    return [f for f in (_post(p) for p in posts) if f is not None]


@register
class BlueskyConnector(ConnectorType):
    kind = "bluesky"
    family = Family.SOURCE
    label = "Bluesky"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE_ACCOUNT
    config_model = BlueskyConfig
    secret_slots = (SecretSlot("app_password", "Mot de passe d'application Bluesky"),)
    egress_domains = ("bsky.social",)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=30)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            await _session(ctx)
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=True, message="session ouverte")
