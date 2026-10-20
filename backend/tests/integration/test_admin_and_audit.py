"""Administration, organization management, audit APIs and bootstrap."""

import re
import time

import asyncpg
import pyotp
import pytest

from app.iam.bootstrap import AdminAlreadyExistsError, bootstrap_admin
from tests.integration.conftest import ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import create_org, create_user

pytestmark = pytest.mark.integration


async def test_admin_invites_and_manages_an_internal_user(
    make_api: ApiFactory, database: Database
) -> None:
    admin = await create_user(
        database.admin_dsn, "admin@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    headers = {"x-csrf-token": await sign_in(api, admin)}

    created = await api.client.post(
        api.url("/admin/users"),
        json={"email": "New.Analyst@cert.example.com", "display_name": "New Analyst"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    user = created.json()
    assert user["email"] == "new.analyst@cert.example.com"
    assert user["status"] == "invited"
    assert "https://backoffice.test/invitation#token=" in api.mailer.outbox[-1].body

    duplicate = await api.client.post(
        api.url("/admin/users"),
        json={"email": "new.analyst@cert.example.com", "display_name": "Dup"},
        headers=headers,
    )
    assert duplicate.status_code == 409

    granted = await api.client.put(
        api.url(f"/admin/users/{user['id']}/workspaces/cert"),
        json={"role": "analyst"},
        headers=headers,
    )
    assert granted.status_code == 204
    detail = (await api.client.get(api.url(f"/admin/users/{user['id']}"))).json()
    assert detail["workspaces"] == [{"slug": "cert", "name": "CERT", "role": "analyst"}]

    page = (await api.client.get(api.url("/admin/users?q=analyst&limit=1"))).json()
    assert [u["email"] for u in page["items"]] == ["new.analyst@cert.example.com"]

    disabled = await api.client.patch(
        api.url(f"/admin/users/{admin.id}"), json={"status": "disabled"}, headers=headers
    )
    assert disabled.status_code == 409  # cannot disable oneself

    audit = (await api.client.get(api.url("/admin/audit?action=admin.membership_set"))).json()
    assert len(audit["items"]) == 1
    assert audit["items"][0]["details"] == {"workspace": "cert", "role": "analyst"}
    assert (await api.client.get(api.url("/admin/audit/verify"))).json()["intact"] is True


async def test_role_changes_require_step_up(make_api: ApiFactory, database: Database) -> None:
    admin = await create_user(
        database.admin_dsn, "admin@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    target = await create_user(database.admin_dsn, "t@cert.example.com")
    api = await make_api("backoffice")
    headers = {"x-csrf-token": await sign_in(api, admin)}
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        await conn.execute("UPDATE sessions SET step_up_at = now() - interval '1 hour'")
    finally:
        await conn.close()
    stale = await api.client.put(
        api.url(f"/admin/users/{target.id}/global-roles/platform_admin"), headers=headers
    )
    assert stale.status_code == 403
    assert stale.json()["detail"] == "step_up_required"

    replayed = await api.client.post(
        api.url("/auth/step-up"), json={"code": admin.totp_now()}, headers=headers
    )
    assert replayed.status_code == 401  # already used at sign-in: replay refused
    assert admin.totp_secret is not None
    next_code = pyotp.TOTP(admin.totp_secret).at(int(time.time()) + 30)  # next window is accepted
    stepped = await api.client.post(
        api.url("/auth/step-up"), json={"code": next_code}, headers=headers
    )
    assert stepped.status_code == 200
    granted = await api.client.put(
        api.url(f"/admin/users/{target.id}/global-roles/platform_admin"), headers=headers
    )
    assert granted.status_code == 204


async def test_client_admin_manages_only_its_organization(
    make_api: ApiFactory, database: Database
) -> None:
    acme = await create_org(database.admin_dsn, "Acme")
    globex = await create_org(database.admin_dsn, "Globex")
    referent = await create_user(
        database.admin_dsn,
        "ref@acme.example.com",
        user_type="client",
        client_org=acme,
        client_role="client_admin",
    )
    other = await create_user(
        database.admin_dsn, "g@globex.example.com", user_type="client", client_org=globex
    )
    api = await make_api("portal")
    headers = {"x-csrf-token": await sign_in(api, referent)}

    invited = await api.client.post(
        api.url("/org/users"),
        json={"email": "colleague@acme.example.com", "display_name": "Colleague"},
        headers=headers,
    )
    assert invited.status_code == 201, invited.text
    assert "https://portal.test/invitation#token=" in api.mailer.outbox[-1].body

    listed = (await api.client.get(api.url("/org/users"))).json()
    assert {u["email"] for u in listed["items"]} == {
        "ref@acme.example.com",
        "colleague@acme.example.com",
    }
    foreign = await api.client.patch(
        api.url(f"/org/users/{other.id}"), json={"status": "disabled"}, headers=headers
    )
    assert foreign.status_code == 404
    self_change = await api.client.patch(
        api.url(f"/org/users/{referent.id}"), json={"role": "client_user"}, headers=headers
    )
    assert self_change.status_code == 409


async def test_workspace_audit_is_limited_to_members(
    make_api: ApiFactory, database: Database
) -> None:
    admin = await create_user(
        database.admin_dsn, "admin@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    cert = await create_user(
        database.admin_dsn, "c@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    target = await create_user(database.admin_dsn, "t@cert.example.com")
    api = await make_api("backoffice")
    headers = {"x-csrf-token": await sign_in(api, admin)}
    await api.client.put(
        api.url(f"/admin/users/{target.id}/workspaces/voc"),
        json={"role": "viewer"},
        headers=headers,
    )
    await api.client.put(
        api.url(f"/admin/users/{target.id}/workspaces/cert"),
        json={"role": "viewer"},
        headers=headers,
    )

    api.client.cookies.clear()
    await sign_in(api, cert)
    cert_events = (await api.client.get(api.url("/workspaces/cert/audit"))).json()["items"]
    assert [e["details"]["workspace"] for e in cert_events] == ["cert"]
    assert (await api.client.get(api.url("/workspaces/voc/audit"))).status_code == 404
    assert (await api.client.get(api.url("/admin/audit"))).status_code == 403


async def test_audit_export_is_json_lines(make_api: ApiFactory, database: Database) -> None:
    admin = await create_user(
        database.admin_dsn, "admin@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    await sign_in(api, admin)
    response = await api.client.get(api.url("/admin/audit/export"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    actions = [line.split('"action": "')[1].split('"')[0] for line in response.text.splitlines()]
    assert actions[0] == "auth.login"
    assert actions[-1] == "audit.exported"


async def test_bootstrap_admin_once(make_api: ApiFactory, database: Database) -> None:
    api = await make_api("backoffice")
    settings = api.app.state.settings
    link = await bootstrap_admin(settings, "First@VOC.example.com", "First Admin")
    token = re.search(r"#token=([\w-]+)", link)
    assert token
    with pytest.raises(AdminAlreadyExistsError):
        await bootstrap_admin(settings, "second@voc.example.com", "Second")

    accepted = await api.client.post(
        api.url("/auth/invitation/accept"),
        json={"token": token[1], "password": "blue whale under the moon"},
    )
    assert accepted.status_code == 204
    login = await api.client.post(
        api.url("/auth/login"),
        json={"email": "first@voc.example.com", "password": "blue whale under the moon"},
    )
    assert login.json()["status"] == "mfa_enrollment_required"
