"""Authorization matrix: every profile against representative routes (RBAC.md §5).

Out-of-scope resources answer 404 (existence not disclosed); missing permissions 403.
"""

import pytest

from app.core.config import Audience
from tests.integration.conftest import ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import SeededUser, create_org, create_user

pytestmark = pytest.mark.integration

ANON = "anonymous"

BACKOFFICE_MATRIX: dict[str, dict[str, int]] = {
    # route: {profile: expected status}
    "/admin/users": {ANON: 401, "voc": 200, "cert": 403, "viewer": 403, "no_workspace": 403},
    "/admin/clients": {ANON: 401, "voc": 200, "cert": 403, "viewer": 403, "no_workspace": 403},
    "/admin/workspaces": {ANON: 401, "voc": 200, "cert": 403, "viewer": 403, "no_workspace": 403},
    "/admin/audit": {ANON: 401, "voc": 200, "cert": 403, "viewer": 403, "no_workspace": 403},
    "/workspaces/voc/audit": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/cert/audit": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/workspaces/voc/secrets": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/cert/secrets": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/admin/secrets": {ANON: 401, "voc": 200, "cert": 403, "viewer": 403, "no_workspace": 403},
    "/workspaces/voc/connectors/source": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/cert/connectors/ai_engine": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/admin/connectors/publish": {
        ANON: 401,
        "voc": 200,
        "cert": 403,
        "viewer": 403,
        "no_workspace": 403,
    },
    "/connector-types": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 200},
    # Shared vulnerability data: every member reads it, viewers included (ADR-024).
    "/vulnerabilities": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 403},
    "/cves": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 403},
    "/cves/sync-status": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 403},
    "/technologies": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 403},
    "/node-types": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 200},
    "/workspaces/voc/bulletin-templates": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/voc/bulletins": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/voc/bulletin-audiences": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/cert/draft-requests": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/ai-models": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 403},
    "/admin/ai-engine": {ANON: 401, "voc": 200, "cert": 403, "viewer": 403, "no_workspace": 403},
    "/workspaces/cert/ai-engine": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/workspaces/voc/workflows": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 200,
        "no_workspace": 404,
    },
    "/workspaces/cert/workflows": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    # Agents are read like workflows (viewers included), inside their workspace only.
    "/workspaces/voc/agents": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 200,
        "no_workspace": 404,
    },
    "/workspaces/cert/agent-runs": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/workspaces/voc/ai-budget": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 200,
        "no_workspace": 404,
    },
    "/workspaces/cert/ai-evaluation/runs": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/workspaces/voc/ai-evaluation/cases": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 200,
        "no_workspace": 404,
    },
    "/workspaces/cert/x-coverage": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/workspaces/voc/watch-scope": {
        ANON: 401,
        "voc": 200,
        "cert": 404,
        "viewer": 403,
        "no_workspace": 404,
    },
    "/workspaces/cert/sources": {
        ANON: 401,
        "voc": 404,
        "cert": 200,
        "viewer": 404,
        "no_workspace": 404,
    },
    "/account/sessions": {ANON: 401, "voc": 200, "cert": 200, "viewer": 200, "no_workspace": 200},
}

PORTAL_MATRIX: dict[str, dict[str, int]] = {
    "/org/users": {ANON: 401, "client_user": 403, "client_admin": 200},
    "/account/sessions": {ANON: 401, "client_user": 200, "client_admin": 200},
}


async def _profiles(database: Database) -> dict[str, SeededUser]:
    dsn = database.admin_dsn
    acme = await create_org(dsn, "Acme")
    return {
        "voc": await create_user(
            dsn, "voc@v.example.com", workspaces={"voc": "analyst"}, with_totp=True
        ),
        "cert": await create_user(
            dsn, "cert@c.example.com", workspaces={"cert": "analyst"}, with_totp=True
        ),
        "viewer": await create_user(
            dsn, "viewer@v.example.com", workspaces={"voc": "viewer"}, with_totp=True
        ),
        "no_workspace": await create_user(dsn, "none@n.example.com", with_totp=True),
        "client_user": await create_user(
            dsn, "u@acme.example.com", user_type="client", client_org=acme
        ),
        "client_admin": await create_user(
            dsn,
            "a@acme.example.com",
            user_type="client",
            client_org=acme,
            client_role="client_admin",
        ),
    }


@pytest.mark.parametrize(
    ("audience", "matrix"), [("backoffice", BACKOFFICE_MATRIX), ("portal", PORTAL_MATRIX)]
)
async def test_authorization_matrix(
    make_api: ApiFactory, database: Database, audience: Audience, matrix: dict[str, dict[str, int]]
) -> None:
    users = await _profiles(database)
    api = await make_api(audience)
    profiles = sorted({p for expectations in matrix.values() for p in expectations})
    failures: list[str] = []
    for profile in profiles:
        api.client.cookies.clear()
        if profile != ANON:
            await sign_in(api, users[profile])
        for route, expectations in matrix.items():
            if profile not in expectations:
                continue
            status = (await api.client.get(api.url(route))).status_code
            if status != expectations[profile]:
                failures.append(f"{profile} GET {route}: {status} != {expectations[profile]}")
    assert failures == []
