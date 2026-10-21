"""Vendor advisory pages (spec 07 §2): a workspace connector listing the domains its
pages live on. robots.txt is honoured, pages are reduced to text (scripts, styles and
markup dropped), never rendered, never executed."""

from html.parser import HTMLParser
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

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
from app.connectors.types.rss import host_allowed
from app.core.narrow import expect

MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_TEXT = 100_000
AGENT = "vuln-veille"
SKIPPED = frozenset({"script", "style", "noscript", "template", "svg", "iframe", "object", "head"})
BLOCKS = frozenset({"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "td"})


class WebConfig(ConnectorConfig):
    allowed_domains: list[str] = Field(
        min_length=1,
        max_length=50,
        description="Domaines des pages d'avis, par ex. msrc.microsoft.com",
    )
    health_url: str | None = Field(default=None, max_length=2048)

    @field_validator("allowed_domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        from app.connectors.types.rss import RssConfig  # noqa: PLC0415 - same rules

        return RssConfig.model_validate({"allowed_domains": value}).allowed_domains


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.in_title = False
        self.title = ""
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in SKIPPED and tag != "head":
            self.skip += 1
        elif tag == "title":
            self.in_title = True
        elif tag in BLOCKS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in SKIPPED and tag != "head" and self.skip:
            self.skip -= 1
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data
        elif not self.skip:
            self.parts.append(data)


def page_text(html: str) -> tuple[str, str]:
    parser = _Text()
    parser.feed(html)
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    text = "\n".join(line for line in lines if line)
    return " ".join(parser.title.split())[:500], text[:MAX_TEXT]


async def _allowed_by_robots(
    ctx: ConnectorContext, url: str, cache: dict[str, RobotFileParser]
) -> bool:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    robots = cache.get(origin)
    if robots is None:
        robots = RobotFileParser()
        response = await fetch(ctx, "GET", f"{origin}/robots.txt", ok=(200, 401, 403, 404, 410))
        if response.status_code == 200:  # noqa: PLR2004
            robots.parse(response.text.splitlines())
        elif response.status_code in (401, 403):  # access to robots.txt refused: stay away
            robots.parse(["User-agent: *", "Disallow: /"])
        else:  # no robots.txt: everything is allowed
            robots.parse([])
        cache[origin] = robots
    return robots.can_fetch(AGENT, url)


async def read_page(
    ctx: ConnectorContext, url: str, robots: dict[str, RobotFileParser] | None = None
) -> Found:
    config = expect(ctx.config, WebConfig)
    if not url.startswith("https://") or not host_allowed(url, config.allowed_domains):
        raise FetchError("domain_not_allowed")
    if not await _allowed_by_robots(ctx, url, robots if robots is not None else {}):
        raise FetchError("disallowed_by_robots_txt")
    response = await fetch(ctx, "GET", url)
    title, text = page_text(response.text)
    return Found(source="web", url=response.url, title=title, content=text)


@register
class WebConnector(ConnectorType):
    kind = "web"
    family = Family.SOURCE
    label = "Pages web (avis éditeurs)"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = WebConfig
    content_types = ("text/html", "application/xhtml+xml", "text/plain")
    max_response_bytes = MAX_PAGE_BYTES
    default_quotas = Quotas(requests_per_minute=30)

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        return tuple(expect(config, WebConfig).allowed_domains)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        config = expect(ctx.config, WebConfig)
        if not config.health_url:
            return HealthResult(ok=True, message="aucune page de test configurée")
        try:
            found = await read_page(ctx, config.health_url)
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=bool(found.content), message="page lisible")
