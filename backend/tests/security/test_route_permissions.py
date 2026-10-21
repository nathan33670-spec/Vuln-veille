"""Deny-by-default guard: every route must declare an access policy (RBAC.md §5)."""

import pytest
from fastapi import APIRouter

from app.app_factory import API_PREFIX, create_app
from app.core.access import route_policies
from app.core.config import Audience
from tests.conftest import make_settings

# Framework routes that carry no business data; anything else must declare a policy.
FRAMEWORK_SUFFIXES = ("/docs", "/openapi.json", "/docs/oauth2-redirect")

# Routes allowed to be public. Adding one here requires a security review.
PUBLIC_ROUTE_SUFFIXES = {
    "GET /healthz",
    "GET /readyz",
    "POST /auth/login",
    "POST /auth/invitation/accept",
    "POST /auth/password/forgot",
    "POST /auth/password/reset",
    # Signed with HMAC-SHA256 (spec 02 §6); verified by the worker holding the key.
    "POST /hooks/{trigger_id}",
}

AUDIENCES: list[Audience] = ["backoffice", "portal"]


def _normalize(route: str, audience: Audience) -> str:
    method, path = route.split(" ", 1)
    return f"{method} {path.removeprefix(API_PREFIX[audience])}"


def _is_framework(route: str) -> bool:
    return route.split(" ", 1)[1].endswith(FRAMEWORK_SUFFIXES)


@pytest.mark.parametrize("audience", AUDIENCES)
def test_every_route_declares_an_access_policy(audience: Audience) -> None:
    policies = route_policies(create_app(audience, make_settings()))
    assert len(policies) >= 10, "route enumeration found too few routes: guard is broken"
    missing = [r for r, p in policies.items() if not _is_framework(r) and not p]
    assert missing == [], f"routes without access policy: {missing}"


@pytest.mark.parametrize("audience", AUDIENCES)
def test_public_routes_are_explicitly_allowlisted(audience: Audience) -> None:
    policies = route_policies(create_app(audience, make_settings()))
    public = {_normalize(r, audience) for r, p in policies.items() if "public" in p}
    assert public <= PUBLIC_ROUTE_SUFFIXES, (
        f"unexpected public routes: {public - PUBLIC_ROUTE_SUFFIXES}"
    )


def test_guard_detects_an_undeclared_route_in_an_included_router() -> None:
    app = create_app("backoffice", make_settings())
    router = APIRouter()

    @router.get("/forgotten")
    async def forgotten() -> None:
        return None

    app.include_router(router, prefix="/api/v1/nested")
    policies = route_policies(app)
    assert policies["GET /api/v1/nested/forgotten"] == []
