"""Generic HTTP publication connector (``publish.http_generic``, spec 05, ADR-030).

Pushes a validated bulletin to an API nobody knew in advance: request, authentication,
payload mapping, success criteria and retries are configuration. Every slot is
optional for the framework; the authentication type decides which ones are required
(checked when the connector is saved).
"""

from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING

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
from app.core.errors import ApiError
from app.core.narrow import expect
from app.net.safe_http import EgressPolicy
from app.publish.config import REQUIRED_SLOTS, HttpGenericConfig
from app.publish.context import PublishError
from app.publish.oauth import oauth_token
from app.publish.request import authenticate

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.connectors.models import Connector

MIB = 1024 * 1024


@register
class HttpGenericConnector(ConnectorType):
    kind = "http_generic"
    family = Family.PUBLISH
    label = "API HTTP générique (publication)"
    scopes = frozenset({Scope.WORKSPACE, Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = HttpGenericConfig
    secret_slots = (
        SecretSlot("credential", "Clé d'API ou jeton (clé API, bearer)", False),
        SecretSlot("username", "Identifiant (basic)", False),
        SecretSlot("password", "Mot de passe (basic)", False),
        SecretSlot("client_id", "Identifiant client (OAuth2)", False),
        SecretSlot("client_secret", "Secret client (OAuth2)", False),
        SecretSlot("client_certificate", "Certificat client PEM (mTLS)", False),
        SecretSlot("client_key", "Clé privée PEM (mTLS)", False),
        SecretSlot("signing_key", "Clé de signature (HMAC)", False),
        SecretSlot("ca_bundle", "Autorité de certification PEM (facultatif)", False),
    )
    max_response_bytes = MIB

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        return expect(config, HttpGenericConfig).hosts()

    @classmethod
    def adjust_policy(
        cls, config: ConnectorConfig, secrets: Mapping[str, str], policy: EgressPolicy
    ) -> EgressPolicy:
        config = expect(config, HttpGenericConfig)
        timeout = float(config.request.timeout_seconds)
        mtls = config.auth.type == "mtls"
        return replace(
            policy,
            read_timeout=timeout,
            total_timeout=timeout * 2,
            # Plain HTTP only towards a private range an administrator approved.
            allow_http=config.uses_http() and bool(policy.private_networks),
            max_redirects=0,  # a publication never follows a redirect elsewhere
            ca_bundle_pem=secrets.get("ca_bundle") or None,
            client_cert_pem=secrets.get("client_certificate") if mtls else None,
            client_key_pem=secrets.get("client_key") if mtls else None,
        )

    async def on_saved(self, db: "AsyncSession", connector: "Connector") -> None:
        config = HttpGenericConfig.model_validate(connector.config)
        missing = [s for s in REQUIRED_SLOTS[config.auth.type] if s not in connector.secret_refs]
        if missing:
            raise ApiError(
                422,
                "missing_secret",
                [{"loc": ["secret_refs", slot], "type": "missing"} for slot in missing],
            )

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        """The token endpoint answers (OAuth2), then a GET on ``health_path`` with the
        connector's credentials; without a health path nothing else is contacted."""
        config = expect(ctx.config, HttpGenericConfig)
        token = None
        try:
            if config.auth.type == "oauth2_client_credentials":
                token = await oauth_token(
                    ctx.http, config, dict(ctx.secrets), cache_key=(str(ctx.connector_id), -1)
                )
            if not config.request.health_path:
                return HealthResult(ok=True, message="oauth_ok" if token else "no_health_path")
            headers: dict[str, str] = {}
            url = config.request.base_url + config.request.health_path
            url, _ = authenticate(config, headers, url, b"", ctx.secrets, token, None)
        except PublishError as exc:
            return HealthResult(ok=False, message=exc.code)
        response = await ctx.http.get(url, headers=headers)
        return HealthResult(ok=response.status_code < 400, message=f"http_{response.status_code}")  # noqa: PLR2004
