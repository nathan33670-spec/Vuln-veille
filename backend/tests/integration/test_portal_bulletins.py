"""The client portal shows the bulletins meant for the organisation, and nothing else
(phase 8, 8A, plan 8.5): TLP rules (Q22), chosen audiences, never a draft, never an
update before it is published again, never a withdrawn bulletin, never another
organisation's bulletin, never an internal field; the portal role reads the views only.
"""

import uuid
from typing import Any

import asyncpg
import pytest

from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.publish_support import (
    Client,
    login,
    seed_all_templates,
    sql,
    validated_bulletin,
)
from tests.integration.seed import WORKSPACE_IDS, create_org, create_user

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]
ALLOWED_KEYS = {
    "id", "ref", "title", "severity", "tlp", "language", "team", "cves", "technologies",
    "published_at", "updated_at",
}  # fmt: skip


class Portal:
    def __init__(self, api: Api) -> None:
        self.api = api

    async def get(self, path: str, status: int = 200, **params: Any) -> Any:
        response = await self.api.client.get(self.api.url(path), params=params)
        assert response.status_code == status, response.text
        return response.json() if "json" in response.headers.get("content-type", "") else response

    async def refs(self, **params: Any) -> set[str]:
        page = await self.get("/bulletins", **params)
        return {b["ref"] for b in page["items"]}


async def _portal(make_api: ApiFactory, database: Database, email: str, org: uuid.UUID) -> Portal:
    user = await create_user(database.admin_dsn, email, user_type="client", client_org=org)
    api = await make_api("portal")
    await sign_in(api, user)
    return Portal(api)


async def _publish(e: Client, bulletin: uuid.UUID) -> dict[str, Any]:
    current = await e.call("GET", f"/workspaces/cert/bulletins/{bulletin}")
    return dict(
        await e.call(
            "POST",
            f"/workspaces/cert/bulletins/{bulletin}/publish",
            {"version": current["version"]},
        )
    )


async def _ref(database: Database, bulletin: uuid.UUID) -> str:
    return str((await sql(database, "SELECT ref FROM bulletins WHERE id = $1", bulletin))[0]["ref"])


async def test_portal_sees_only_what_was_published_for_it(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    acme = await create_org(database.admin_dsn, "Acme")
    beta = await create_org(database.admin_dsn, "Beta")
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    e = await login(make_api, eve)

    async def bulletin(title: str, tlp: str, audience: list[uuid.UUID] | None = None,
                       publish: bool = True) -> tuple[uuid.UUID, str]:  # fmt: skip
        created = await validated_bulletin(
            database, CERT, "approved", title=title, tlp=tlp, audience=audience
        )
        if publish:
            await _publish(e, created)
        return created, await _ref(database, created)

    _, everyone = await bulletin("Faille Apache pour tous", "GREEN")
    _, acme_only = await bulletin("Faille ciblée Acme", "GREEN", [acme])
    beta_amber_id, beta_amber = await bulletin("Faille AMBER Beta", "AMBER", [beta])
    await bulletin("AMBER sans cible", "AMBER")  # AMBER needs chosen organisations
    await bulletin("Faille RED", "RED", [acme, beta])  # RED never reaches the portal
    await bulletin("Pas encore publié", "GREEN", publish=False)
    withdrawn_id, _ = await bulletin("Retiré", "GREEN")
    current = await e.call("GET", f"/workspaces/cert/bulletins/{withdrawn_id}")
    await e.call(
        "POST", f"/workspaces/cert/bulletins/{withdrawn_id}/withdraw",
        {"reason": "Erreur", "version": current["version"]},
    )  # fmt: skip

    a = await _portal(make_api, database, "alice@acme.example", acme)
    b = await _portal(make_api, database, "bob@beta.example", beta)
    assert await a.refs() == {everyone, acme_only}
    assert await b.refs() == {everyone, beta_amber}

    # Another organisation's bulletin does not exist for this one.
    await a.get(f"/bulletins/{beta_amber_id}", 404)
    await a.get(f"/bulletins/{beta_amber_id}/export", 404, format="markdown")

    # Allow-listed fields only: nothing internal.
    page = await a.get("/bulletins")
    for item in page["items"]:
        assert set(item) == ALLOWED_KEYS
        assert item["team"] == "CERT"
    detail = await b.get(f"/bulletins/{beta_amber_id}")
    assert set(detail) == ALLOWED_KEYS | {"html", "history"}
    assert [h["kind"] for h in detail["history"]] == ["published"]

    # Search and filters.
    assert await a.refs(q="Apache") == {everyone}
    assert await a.refs(q=acme_only) == {acme_only}
    assert await a.refs(q="inexistant") == set()
    assert await a.refs(severity=["critical"]) == set()  # none carries a severity here
    assert await a.refs(since="2999-01-01") == set()
    assert await a.refs(until="2999-01-01") == {everyone, acme_only}
    assert await a.refs(technology="inconnue") == set()
    exported = await a.get(f"/bulletins/{(page['items'][0])['id']}/export", format="html")
    assert exported.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in exported.text
    assert "attachment" in exported.headers["content-disposition"]


async def test_an_update_reaches_clients_only_once_published(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    acme = await create_org(database.admin_dsn, "Acme")
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    e = await login(make_api, eve)
    bulletin = await validated_bulletin(database, CERT, "approved", title="Version publiée")
    await _publish(e, bulletin)
    a = await _portal(make_api, database, "alice@acme.example", acme)

    # An update in progress: new title, then RED marking; the portal keeps what was
    # published, title and marking included.
    current = await e.call("GET", f"/workspaces/cert/bulletins/{bulletin}")
    fields = {**current["current"]["fields"], "title": "Brouillon confidentiel"}
    current = await e.call(
        "POST", f"/workspaces/cert/bulletins/{bulletin}/revisions",
        {"fields": fields, "base_rev_no": current["current"]["rev_no"]}, 201,
    )  # fmt: skip
    current = await e.call(
        "PATCH", f"/workspaces/cert/bulletins/{bulletin}",
        {"tlp": "RED", "version": current["version"]},
    )  # fmt: skip
    shown = await a.get(f"/bulletins/{bulletin}")
    assert (shown["title"], shown["tlp"]) == ("Version publiée", "GREEN")
    assert "Brouillon" not in shown["html"]

    # Back to GREEN, approved and published again: the update reaches the client.
    current = await e.call(
        "PATCH", f"/workspaces/cert/bulletins/{bulletin}",
        {"tlp": "GREEN", "version": current["version"]},
    )  # fmt: skip
    current = await e.call(
        "POST", f"/workspaces/cert/bulletins/{bulletin}/approve", {"version": current["version"]}
    )
    await _publish(e, bulletin)
    shown = await a.get(f"/bulletins/{bulletin}")
    assert shown["title"] == "Brouillon confidentiel"
    assert [h["kind"] for h in shown["history"]] == ["updated", "published"]


async def test_the_portal_role_reads_the_views_only(
    database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    bulletin = await validated_bulletin(database, CERT, "approved")
    await sql(
        database,
        "UPDATE bulletins SET status = 'published', published_revision_id = current_revision_id "
        "WHERE id = $1",
        bulletin,
    )
    conn = await asyncpg.connect(database.dsn("vv_portal", PASSWORDS.portal))
    try:
        for relation in (
            "bulletins", "bulletin_revisions", "bulletin_publication_events",
            "portal_published_v", "vulnerabilities", "workspaces",
        ):  # fmt: skip
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.fetch(f"SELECT 1 FROM {relation} LIMIT 1")  # noqa: S608 - fixed names
        # Without an organisation in the context, the view is empty.
        assert await conn.fetch("SELECT id FROM portal_bulletins_v") == []
    finally:
        await conn.close()
    for role, password in (("vv_app", PASSWORDS.app), ("vv_worker", PASSWORDS.worker)):
        conn = await asyncpg.connect(database.dsn(role, password))
        try:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.fetch("SELECT 1 FROM portal_published_v LIMIT 1")
        finally:
            await conn.close()
