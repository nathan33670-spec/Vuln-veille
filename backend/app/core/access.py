"""Route access policy markers.

Every route must declare its access policy through a dependency: either
``public_endpoint`` or a permission check (added in phase 1). The test
``tests/security/test_route_permissions.py`` fails if a route declares none,
which makes authorization deny-by-default at review time.
"""

from collections.abc import Callable, Iterator
from typing import Any

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

POLICY_ATTR = "__vv_access_policy__"


def public_endpoint() -> None:
    """Marker dependency: the route is intentionally reachable without authentication."""


setattr(public_endpoint, POLICY_ATTR, "public")


def _policies(dependant: Dependant) -> Iterator[str]:
    call: Callable[..., Any] | None = dependant.call
    policy = getattr(call, POLICY_ATTR, None) if call is not None else None
    if policy is not None:
        yield str(policy)
    for sub in dependant.dependencies:
        yield from _policies(sub)


def route_policies(app: FastAPI) -> dict[str, list[str]]:
    """Maps ``"METHODS path"`` to the access policies declared on that route."""
    result: dict[str, list[str]] = {}
    for route in app.routes:
        if isinstance(route, APIRoute):
            key = f"{','.join(sorted(route.methods or ()))} {route.path}"
            result[key] = list(_policies(route.dependant))
    return result
