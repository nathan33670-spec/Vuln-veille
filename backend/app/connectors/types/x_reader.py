"""Free reading of X (spec 07 §2.1): no paid API, no scraping, no session tokens.

- Discovery (layer 1): post URLs already cited by collected sources are extracted
  with ``discover_post_urls``; layer 2 is the AI engine's own web search restricted to
  x.com (agent tool ``x_discover``), counted in this connector's quotas.
- Reading: the official oEmbed endpoint (``publish.x.com/oembed``), free and without
  authentication; the returned HTML is reduced to text. A post deleted or made
  private is reported as withdrawn.
- Strictly what is needed: at most ``max_reads_per_cve`` reads per CVE; nothing but the
  URL, the public author handle, the date and the text is kept.
"""

import re
from datetime import UTC, datetime
from html.parser import HTMLParser

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
from app.connectors.found import FetchError, Found, fetch, json_of

OEMBED = "https://publish.x.com/oembed"
# A public post URL: x.com or twitter.com, a handle, /status/, a numeric id.
X_DOMAINS = ("x.com", "twitter.com")
POST_URL = re.compile(
    r"https?://(?:www\.|mobile\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status(?:es)?/(\d{5,25})",
    re.IGNORECASE,
)
HEALTH_POST = "https://x.com/X/status/1585341984679469056"
MAX_DISCOVERED = 50


class XReaderConfig(ConnectorConfig):
    max_reads_per_cve: int = Field(default=5, ge=1, le=20, description="Lectures oEmbed par CVE")
    # The engine's search runs on the provider's side, outside our egress proxy. On by
    # default (project owner's choice, ADR-028); a workspace can turn it off.
    engine_web_search: bool = Field(
        default=True,
        description="Couche 2 : recherche web du moteur IA restreinte à x.com (Q32) ; "
        "le trafic de recherche passe chez le fournisseur IA, hors de notre proxy "
        "(décocher pour s'en tenir aux liens déjà collectés)",
    )


def canonical(handle: str, post_id: str) -> str:
    return f"https://x.com/{handle}/status/{post_id}"


def discover_post_urls(text: str) -> list[str]:
    """Layer 1: X post URLs cited in already collected content (deduplicated)."""
    seen: dict[str, None] = {}
    for handle, post_id in POST_URL.findall(text or ""):
        seen.setdefault(canonical(handle, post_id), None)
        if len(seen) >= MAX_DISCOVERED:
            break
    return list(seen)


class _Blockquote(HTMLParser):
    """Text of the post (the ``<p>``) and the date (the last link's text)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.depth_p = 0
        self.in_link = False
        self.text: list[str] = []
        self.link_text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "p":
            self.depth_p += 1
        elif tag == "a" and not self.depth_p:
            self.in_link, self.link_text = True, ""
        elif tag == "br" and self.depth_p:
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag == "p" and self.depth_p:
            self.depth_p -= 1
        elif tag == "a":
            self.in_link = False

    def handle_data(self, data: str) -> None:
        if self.depth_p:
            self.text.append(data)
        elif self.in_link:
            self.link_text += data


def _date(text: str) -> datetime | None:
    try:
        return datetime.strptime(text.strip(), "%B %d, %Y")
    except ValueError:
        return None


async def read_post(ctx: ConnectorContext, url: str) -> Found | None:
    """The text of one public post; None when it was deleted or made private."""
    match = POST_URL.match(url.strip())
    if match is None:
        raise FetchError("not_an_x_post_url")
    target = canonical(*match.groups())
    response = await fetch(
        ctx,
        "GET",
        OEMBED,
        ok=(200, 403, 404),
        params={"url": target, "omit_script": "1", "dnt": "true"},
    )
    if response.status_code != 200:  # noqa: PLR2004
        return None
    data = json_of(response)
    if not isinstance(data, dict) or not isinstance(data.get("html"), str):
        raise FetchError("unexpected_answer")
    parser = _Blockquote()
    parser.feed(data["html"][:200_000])
    text = " ".join("".join(parser.text).split())
    author = str(data.get("author_url") or "").rstrip("/").rsplit("/", 1)[-1][:50]
    published = _date(parser.link_text)
    return Found(
        source="x_reader",
        url=target,
        title=f"@{author}" if author else "X",
        content=text,
        author=f"@{author}" if author else "",
        published_at=published.replace(tzinfo=UTC) if published else None,
        extra={"cache_age": data.get("cache_age")},
    )


@register
class XReaderConnector(ConnectorType):
    kind = "x_reader"
    family = Family.SOURCE
    label = "X (lecture gratuite : oEmbed officiel)"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = XReaderConfig
    egress_domains = ("publish.x.com",)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=20, requests_per_day=500)
    max_response_bytes = 512 * 1024

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            post = await read_post(ctx, HEALTH_POST)
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=post is not None, message="oEmbed accessible")
