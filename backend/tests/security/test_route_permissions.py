"""Deny-by-default guard: every route must declare an access policy (RBAC.md §5)."""

import pytest
from app.app_factory import create_app
from app.core.access import route_policies

from tests.conftest import make_settings

# Framework routes that carry no business data; anything else must declare a policy.
FRAMEWORK_ROUTES = {
    "GET,HEAD /api/v1/docs",
    "GET,HEAD /api/portal/v1/docs",
    "GET,HEAD /api/v1/openapi.json",
    "GET,HEAD /api/portal/v1/openapi.json",
    "GET,HEAD /api/v1/docs/oauth2-redirect",
    "GET,HEAD /api/portal/v1/docs/oauth2-redirect",
}

# Routes allowed to be public. Adding one here requires a security review.
PUBLIC_ROUTES = {"GET /healthz", "GET /readyz"}


@pytest.mark.parametrize("audience", ["backoffice", "portal"])
def test_every_route_declares_an_access_policy(audience: str) -> None:
    app = create_app(audience, make_settings())  # type: ignore[arg-type]
    missing = [
        route
        for route, policies in route_policies(app).items()
        if route not in FRAMEWORK_ROUTES and not policies
    ]
    assert missing == [], f"routes without access policy: {missing}"


@pytest.mark.parametrize("audience", ["backoffice", "portal"])
def test_public_routes_are_explicitly_allowlisted(audience: str) -> None:
    app = create_app(audience, make_settings())  # type: ignore[arg-type]
    public = {route for route, policies in route_policies(app).items() if "public" in policies}
    assert public <= PUBLIC_ROUTES, f"unexpected public routes: {public - PUBLIC_ROUTES}"
