"""End-to-end authentication flows against PostgreSQL (with RLS) and Redis."""

import re

import asyncpg
import pyotp
import pytest

from tests.integration.conftest import Api, ApiFactory, Database
from tests.integration.seed import DEFAULT_PASSWORD, create_org, create_user

pytestmark = pytest.mark.integration


async def login(api: Api, email: str, password: str = DEFAULT_PASSWORD) -> dict[str, str]:
    response = await api.client.post(
        api.url("/auth/login"), json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    body: dict[str, str] = response.json()
    return body


def csrf(token: str) -> dict[str, str]:
    return {"x-csrf-token": token}


async def test_internal_user_must_enrol_mfa_before_anything(
    make_api: ApiFactory, database: Database
) -> None:
    await create_user(database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"})
    api = await make_api("backoffice")

    body = await login(api, "ana@voc.example.com")
    assert body["status"] == "mfa_enrollment_required"
    token = body["csrf_token"]

    blocked = await api.client.get(api.url("/account/sessions"))
    assert blocked.status_code == 401
    assert blocked.json()["detail"] == "mfa_required"
    me = (await api.client.get(api.url("/auth/me"))).json()
    assert me["pending_mfa"] is True
    assert me["permissions"] == []  # nothing is disclosed before the second factor

    enrollment = (await api.client.post(api.url("/auth/mfa/enroll"), headers=csrf(token))).json()
    code = pyotp.TOTP(enrollment["secret"]).now()
    confirmed = await api.client.post(
        api.url("/auth/mfa/enroll/confirm"), json={"code": code}, headers=csrf(token)
    )
    assert confirmed.status_code == 200, confirmed.text
    assert len(confirmed.json()["recovery_codes"]) == 10
    new_token = confirmed.json()["csrf_token"]
    assert new_token != token  # session rotated

    me = (await api.client.get(api.url("/auth/me"))).json()
    assert me["pending_mfa"] is False
    assert me["mfa_enabled"] is True
    assert "iam.users.manage" in me["permissions"]  # VOC analysts are platform admins (Q1)
    assert [w["slug"] for w in me["workspaces"]] == ["voc"]


async def test_mfa_login_replay_and_recovery_code(make_api: ApiFactory, database: Database) -> None:
    user = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")

    body = await login(api, user.email)
    assert body["status"] == "mfa_required"
    code = user.totp_now()
    ok = await api.client.post(
        api.url("/auth/mfa/verify"), json={"code": code}, headers=csrf(body["csrf_token"])
    )
    assert ok.status_code == 200
    me = (await api.client.get(api.url("/auth/me"))).json()
    assert "iam.users.manage" not in me["permissions"]  # CERT has no admin (Q1)

    # Same code again on a new login: refused (replay protection).
    api.client.cookies.clear()
    body = await login(api, user.email)
    replay = await api.client.post(
        api.url("/auth/mfa/verify"), json={"code": code}, headers=csrf(body["csrf_token"])
    )
    assert replay.status_code == 401


async def test_wrong_passwords_lock_the_account(make_api: ApiFactory, database: Database) -> None:
    await create_user(database.admin_dsn, "bob@voc.example.com", workspaces={"voc": "analyst"})
    api = await make_api("backoffice")
    for _ in range(5):
        r = await api.client.post(
            api.url("/auth/login"),
            json={"email": "bob@voc.example.com", "password": "wrong password!"},
        )
        assert r.status_code == 401
        assert r.json()["detail"] == "invalid_credentials"
    locked = await api.client.post(
        api.url("/auth/login"), json={"email": "bob@voc.example.com", "password": DEFAULT_PASSWORD}
    )
    assert locked.status_code == 401
    unknown = await api.client.post(
        api.url("/auth/login"),
        json={"email": "nobody@voc.example.com", "password": DEFAULT_PASSWORD},
    )
    assert unknown.json() == locked.json() | {"request_id": unknown.json()["request_id"]}


async def test_login_rate_limit_per_ip(make_api: ApiFactory) -> None:
    api = await make_api("backoffice")
    statuses = []
    for i in range(21):
        r = await api.client.post(
            api.url("/auth/login"),
            json={"email": f"u{i}@x.example.com", "password": "whatever-123"},
        )
        statuses.append(r.status_code)
    assert statuses[-1] == 429
    assert set(statuses[:20]) == {401}


async def test_session_cookie_flags_and_csrf(make_api: ApiFactory, database: Database) -> None:
    org = await create_org(database.admin_dsn, "Acme")
    await create_user(database.admin_dsn, "c@acme.example.com", user_type="client", client_org=org)
    api = await make_api("portal")

    response = await api.client.post(
        api.url("/auth/login"), json={"email": "c@acme.example.com", "password": DEFAULT_PASSWORD}
    )
    assert response.json()["status"] == "authenticated"  # client MFA is optional (Q16)
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("__Host-vv_portal=")
    for flag in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert "domain=" not in cookie.lower()

    missing = await api.client.post(
        api.url("/account/password"),
        json={"current_password": DEFAULT_PASSWORD, "new_password": "another long passphrase"},
    )
    assert missing.status_code == 403
    assert missing.json()["detail"] == "csrf_failed"

    foreign = await api.client.post(
        api.url("/auth/logout"),
        headers={"origin": "https://evil.example", **csrf(response.json()["csrf_token"])},
    )
    assert foreign.status_code == 403
    assert foreign.json()["detail"] == "bad_origin"


async def test_accounts_cannot_cross_applications(make_api: ApiFactory, database: Database) -> None:
    org = await create_org(database.admin_dsn, "Acme")
    await create_user(
        database.admin_dsn, "client@acme.example.com", user_type="client", client_org=org
    )
    await create_user(database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"})
    backoffice = await make_api("backoffice")
    portal = await make_api("portal")

    r1 = await backoffice.client.post(
        backoffice.url("/auth/login"),
        json={"email": "client@acme.example.com", "password": DEFAULT_PASSWORD},
    )
    r2 = await portal.client.post(
        portal.url("/auth/login"),
        json={"email": "ana@voc.example.com", "password": DEFAULT_PASSWORD},
    )
    assert r1.status_code == r2.status_code == 401

    # A portal session cookie is not accepted by the back-office.
    ok = await login(portal, "client@acme.example.com")
    cookie = portal.client.cookies.get("__Host-vv_portal")
    assert ok["status"] == "authenticated"
    assert cookie
    backoffice.client.cookies.set("__Host-vv_bo", cookie, domain="backoffice.test")
    assert (await backoffice.client.get(backoffice.url("/auth/me"))).status_code == 401


async def test_invitation_and_password_reset(make_api: ApiFactory, database: Database) -> None:
    org = await create_org(database.admin_dsn, "Acme")
    user = await create_user(
        database.admin_dsn,
        "new@acme.example.com",
        user_type="client",
        client_org=org,
        status="invited",
    )
    api = await make_api("portal")

    # Issue an invitation the way the admin API does, through the application role.
    from app.iam.models import User  # noqa: PLC0415
    from app.iam.tokens import issue_token, send_invitation  # noqa: PLC0415

    async with api.app.state.sessionmaker() as db:
        from app.core.rls import init_context, set_context  # noqa: PLC0415

        init_context(db)
        await set_context(db, user_id=user.id)
        orm_user = await db.get(User, user.id)
        assert orm_user is not None
        raw = await issue_token(db, api.app.state.settings, orm_user, "invitation", "portal", None)
        await db.commit()
        send_invitation(api.mailer, api.app.state.settings, orm_user, "portal", raw)

    link = api.mailer.outbox[-1].body
    token = re.search(r"#token=([\w-]+)", link)
    assert token
    assert "https://portal.test/invitation#token=" in link

    weak = await api.client.post(
        api.url("/auth/invitation/accept"), json={"token": token[1], "password": "password1234"}
    )
    assert weak.status_code == 400
    assert weak.json()["detail"] == "password_too_common"
    accepted = await api.client.post(
        api.url("/auth/invitation/accept"),
        json={"token": token[1], "password": "a fresh client passphrase"},
    )
    assert accepted.status_code == 204
    reused = await api.client.post(
        api.url("/auth/invitation/accept"),
        json={"token": token[1], "password": "a fresh client passphrase"},
    )
    assert reused.status_code == 400
    assert (await login(api, user.email, "a fresh client passphrase"))["status"] == "authenticated"

    # Password reset: always 202, link by e-mail, all sessions revoked afterwards.
    unknown = await api.client.post(
        api.url("/auth/password/forgot"), json={"email": "x@y.example.com"}
    )
    known = await api.client.post(api.url("/auth/password/forgot"), json={"email": user.email})
    assert unknown.status_code == known.status_code == 202
    reset_token = re.search(r"#token=([\w-]+)", api.mailer.outbox[-1].body)
    assert reset_token
    reset = await api.client.post(
        api.url("/auth/password/reset"),
        json={"token": reset_token[1], "password": "yet another client passphrase"},
    )
    assert reset.status_code == 204
    assert (await api.client.get(api.url("/auth/me"))).status_code == 401  # session revoked


async def test_step_up_guards_recovery_code_regeneration(
    make_api: ApiFactory, database: Database
) -> None:
    user = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    body = await login(api, user.email)
    verified = await api.client.post(
        api.url("/auth/mfa/verify"),
        json={"code": user.totp_now()},
        headers=csrf(body["csrf_token"]),
    )
    token = verified.json()["csrf_token"]

    # The MFA verification itself counts as a fresh step-up.
    ok = await api.client.post(api.url("/account/mfa/recovery-codes"), headers=csrf(token))
    assert ok.status_code == 200

    admin = await asyncpg.connect(database.admin_dsn)
    try:
        await admin.execute("UPDATE sessions SET step_up_at = now() - interval '1 hour'")
    finally:
        await admin.close()
    stale = await api.client.post(api.url("/account/mfa/recovery-codes"), headers=csrf(token))
    assert stale.status_code == 403
    assert stale.json()["detail"] == "step_up_required"


async def test_audit_chain_records_and_detects_tampering(
    make_api: ApiFactory, database: Database
) -> None:
    await create_user(database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"})
    api = await make_api("backoffice")
    await login(api, "ana@voc.example.com")
    await api.client.post(
        api.url("/auth/login"), json={"email": "ana@voc.example.com", "password": "wrong password!"}
    )

    admin = await asyncpg.connect(database.admin_dsn)
    try:
        rows = await admin.fetch("SELECT action, outcome FROM audit_events ORDER BY id")
        assert [(r["action"], r["outcome"]) for r in rows] == [
            ("auth.login", "success"),
            ("auth.login", "failure"),
        ]
        assert await admin.fetchval("SELECT audit_verify()") is None
        await admin.execute("UPDATE audit_events SET outcome = 'success' WHERE id = 2")
        assert await admin.fetchval("SELECT audit_verify()") == 2
    finally:
        await admin.close()

    app_conn = await asyncpg.connect(database.dsn("vv_app", "app-test-password-0123456789abcd"))
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.execute("DELETE FROM audit_events")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.execute("UPDATE audit_events SET outcome = 'denied'")
    finally:
        await app_conn.close()


async def test_portal_role_only_sees_its_request_context(
    database: Database, clean_state: None
) -> None:
    acme = await create_org(database.admin_dsn, "Acme")
    globex = await create_org(database.admin_dsn, "Globex")
    a = await create_user(
        database.admin_dsn, "a@acme.example.com", user_type="client", client_org=acme
    )
    await create_user(
        database.admin_dsn, "g@globex.example.com", user_type="client", client_org=globex
    )
    await create_user(database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"})

    portal = await asyncpg.connect(database.dsn("vv_portal", "portal-test-password-0123456789ab"))
    try:
        assert await portal.fetchval("SELECT count(*) FROM users") == 0
        async with portal.transaction():
            await portal.execute("SELECT set_config('app.client_org_id', $1, true)", str(acme))
            emails = {r["email"] for r in await portal.fetch("SELECT email FROM users")}
            assert emails == {a.email}
            orgs = await portal.fetch("SELECT name FROM client_organizations")
            assert [r["name"] for r in orgs] == ["Acme"]
        async with portal.transaction():
            await portal.execute(
                "SELECT set_config('app.login_email', 'ana@voc.example.com', true)"
            )
            assert await portal.fetchval("SELECT count(*) FROM users") == 0  # internal user
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await portal.fetch("SELECT * FROM workspaces")
    finally:
        await portal.close()
