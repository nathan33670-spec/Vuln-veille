"""Blocking rules of the connector framework (ADR-021, ADR-023, CLAUDE.md)."""

from decimal import Decimal
from pathlib import Path

import pytest

from app.connectors.base import (
    ALLOWED_COSTS,
    ConnectorConfig,
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    Quotas,
    RegistrationError,
    Scope,
    register,
    registered,
    unregister,
)
from app.connectors.egress_acl import render_acl, static_domains

ACL = Path(__file__).resolve().parents[3] / "deploy" / "smokescreen" / "acl.yaml"


def _type(**attributes: object) -> type[ConnectorType]:
    class Config(ConnectorConfig):
        url_path: str = "/"

    async def health_check(self: ConnectorType, ctx: ConnectorContext) -> HealthResult:
        return HealthResult(ok=True)

    values: dict[str, object] = {
        "kind": "test_rules",
        "family": Family.SOURCE,
        "label": "t",
        "scopes": frozenset({Scope.WORKSPACE}),
        "cost_class": CostClass.FREE,
        "config_model": Config,
        "egress_domains": ("api.example.org",),
        "health_check": health_check,
    }
    values.update(attributes)
    return type("RulesType", (ConnectorType,), values)


def test_every_registered_type_is_free_or_ai_billed() -> None:
    for kind, type_ in registered().items():
        assert type_.cost_class in ALLOWED_COSTS, kind
        if type_.cost_class == CostClass.AI_BILLED:
            assert type_.default_quotas.monthly_budget_eur is not None, kind


def test_paid_types_are_refused() -> None:
    with pytest.raises(RegistrationError, match="paid"):
        register(_type(cost_class=CostClass.PAID))
    assert "test_rules" not in registered()


@pytest.mark.parametrize("field", ["api_key", "token", "client_secret", "password", "apiKey"])
def test_credentials_cannot_be_configuration_fields(field: str) -> None:
    config = type("Config", (ConnectorConfig,), {"__annotations__": {field.lower(): str}})
    with pytest.raises(RegistrationError, match="secret slot"):
        register(_type(config_model=config))


@pytest.mark.parametrize("domain", ["", "localhost", "10.0.0.1", "http://x.org", "a..org", "*"])
def test_egress_domains_must_be_valid_names(domain: str) -> None:
    with pytest.raises(RegistrationError):
        register(_type(egress_domains=(domain,)))


def test_ai_billed_types_need_a_budget() -> None:
    with pytest.raises(RegistrationError, match="budget"):
        register(_type(cost_class=CostClass.AI_BILLED))
    budgeted = _type(
        cost_class=CostClass.AI_BILLED, default_quotas=Quotas(monthly_budget_eur=Decimal(5))
    )
    register(budgeted)
    unregister("test_rules")


def test_a_kind_cannot_be_registered_twice() -> None:
    first, second = _type(), _type()
    register(first)
    try:
        with pytest.raises(RegistrationError, match="twice"):
            register(second)
    finally:
        unregister("test_rules")


def test_quotas_are_consistent() -> None:
    with pytest.raises(ValueError, match="exceed"):
        Quotas(requests_per_day=100, requests_per_month=10)


def test_committed_proxy_allow_list_covers_every_declared_domain() -> None:
    allowed = {
        line.strip()[2:] for line in ACL.read_text().splitlines() if line.strip().startswith("- ")
    }
    missing = static_domains() - allowed
    assert not missing, f"run `python -m app.cli egress-acl --static-only`: {sorted(missing)}"


def test_rendered_acl_is_sorted_and_deduplicated() -> None:
    text = render_acl(["b.example.org", "a.example.org", "b.example.org"])
    assert text.endswith("    - a.example.org\n    - b.example.org\n")
