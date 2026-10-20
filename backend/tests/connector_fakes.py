"""A connector type for tests: no network, behaviour driven by its configuration."""

from collections.abc import Iterator
from contextlib import contextmanager

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
    unregister,
)


class EchoConfig(ConnectorConfig):
    fail: bool = False
    limit: int = 1


class EchoSource(ConnectorType):
    kind = "test_echo"
    family = Family.SOURCE
    label = "Test (echo)"
    scopes = frozenset({Scope.GLOBAL, Scope.WORKSPACE})
    cost_class = CostClass.FREE_ACCOUNT
    config_model = EchoConfig
    secret_slots = (SecretSlot("token", "Jeton"),)
    egress_domains = ("echo.example.org",)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        assert isinstance(ctx.config, EchoConfig)
        if ctx.config.fail:
            return HealthResult(ok=False, message="service refused the token")
        # Proves the worker decrypted the secret, without ever exposing it.
        return HealthResult(ok=bool(ctx.secrets.get("token")), message="")


@contextmanager
def echo_type() -> Iterator[type[EchoSource]]:
    register(EchoSource)
    try:
        yield EchoSource
    finally:
        unregister(EchoSource.kind)
