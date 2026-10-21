"""Generic HTTP API source (``source.http``): one base URL, an optional credential
header held in the vault. GET only: a source never changes anything remotely."""

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
    SecretSlot,
    register,
)
from app.core.narrow import expect

_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")


class HttpApiConfig(ConnectorConfig):
    base_url: HttpUrl = Field(description="URL de base HTTPS de l'API")
    auth_header: str = Field(default="Authorization", description="En-tête portant l'identifiant")
    auth_prefix: str = Field(default="", max_length=20, description="Par exemple « Bearer  »")
    health_path: str = Field(default="", max_length=500)

    @field_validator("base_url")
    @classmethod
    def _https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https" or not value.host:
            raise ValueError("https only")
        return value

    @field_validator("auth_header")
    @classmethod
    def _header(cls, value: str) -> str:
        if not _HEADER.fullmatch(value):
            raise ValueError("invalid header name")
        return value


def join(base: str, path: str) -> str:
    if "://" in path or path.startswith("//"):
        raise ValueError("relative paths only")
    return base.rstrip("/") + "/" + path.lstrip("/")


@register
class HttpApiConnector(ConnectorType):
    kind = "http_api"
    family = Family.SOURCE
    label = "API HTTP (lecture)"
    scopes = frozenset({Scope.WORKSPACE})
    cost_class = CostClass.FREE_ACCOUNT
    config_model = HttpApiConfig
    secret_slots = (SecretSlot("credential", "Valeur de l'en-tête d'authentification", False),)
    content_types = ("application/json", "text/plain", "text/csv")
    max_response_bytes = 5 * 1024 * 1024

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        config = expect(config, HttpApiConfig)
        return ((urlsplit(str(config.base_url)).hostname or "").lower(),)

    @staticmethod
    def headers(ctx: ConnectorContext) -> dict[str, str]:
        config = ctx.config
        config = expect(config, HttpApiConfig)
        credential = ctx.secrets.get("credential")
        return {config.auth_header: config.auth_prefix + credential} if credential else {}

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        config = ctx.config
        config = expect(config, HttpApiConfig)
        url = join(str(config.base_url), config.health_path)
        response = await ctx.http.get(url, headers=self.headers(ctx))
        ok = 200 <= response.status_code < 300  # noqa: PLR2004
        return HealthResult(ok=ok, message=f"http_{response.status_code}")
