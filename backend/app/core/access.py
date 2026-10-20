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
from fastapi.routing import APIRoute, iter_route_contexts

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
    """Maps ``"METHODS path"`` to the access policies declared on that route.

    Uses FastAPI's public route iterator, which also walks included routers (FastAPI
    wraps them; iterating ``app.routes`` directly would silently miss their routes).
    """
    result: dict[str, list[str]] = {}
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        if not isinstance(route, APIRoute):
            continue
        dependant: Dependant = getattr(context, "dependant", None) or route.dependant
        path = context.path_format or context.path or route.path
        key = f"{','.join(sorted(context.methods or route.methods or ()))} {path}"
        result[key] = list(_policies(dependant))
    return result
