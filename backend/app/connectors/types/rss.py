"""RSS and Atom feeds (CERT-FR, vendors, blogs): a workspace connector listing the
domains its feeds live on. Feeds are parsed with defusedxml (no entity expansion)."""

import re
from urllib.parse import urlsplit

from pydantic import Field, HttpUrl, field_validator

from app.connectors.base import (
    ConnectorConfig,
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    Scope,
    register,
)
from app.core.narrow import expect
from app.watch.feeds import FEED_TYPES

_DOMAIN = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class RssConfig(ConnectorConfig):
    allowed_domains: list[str] = Field(
        min_length=1, max_length=20, description="Domaines des flux, par ex. www.cert.ssi.gouv.fr"
    )
    health_url: HttpUrl | None = Field(default=None, description="Flux testé par « Tester »")

    @field_validator("allowed_domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        cleaned = sorted({d.strip().lower().rstrip(".") for d in value})
        for domain in cleaned:
            if not _DOMAIN.fullmatch(domain):
                raise ValueError("invalid domain")
        return cleaned


def host_allowed(url: str, domains: list[str]) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return any(
        host == d or (d.startswith("*.") and host.endswith(d[1:]) and host != d[2:])
        for d in domains
    )


@register
class RssConnector(ConnectorType):
    kind = "rss"
    family = Family.SOURCE
    label = "Flux RSS ou Atom"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = RssConfig
    content_types = FEED_TYPES
    max_response_bytes = 5 * 1024 * 1024

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        config = expect(config, RssConfig)
        return tuple(config.allowed_domains)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        config = ctx.config
        config = expect(config, RssConfig)
        if config.health_url is None:
            return HealthResult(ok=True, message="aucun flux de test configuré")
        response = await ctx.http.get(str(config.health_url))
        if response.status_code != 200:  # noqa: PLR2004
            return HealthResult(ok=False, message=f"http_{response.status_code}")
        return HealthResult(ok=True, message="flux accessible")
