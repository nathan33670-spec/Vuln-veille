"""Publication connectors, API side (phase 7, 7A): configuration checked by
authentication type, masked dry-run on a validated bulletin, mapping preview, exports
(CSAF, JSON, Markdown), global targets, and the administrators' approval of a private
range, applied by the worker only while it matches the connector (ADR-030)."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import pytest

from app.bulletins.seeds import seed_templates
from app.connectors.models import Connector
from app.connectors.runtime import approved_networks
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, SeededUser, create_user
from tests.integration.workflow_harness import harness

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]
CONFIG: dict[str, Any] = {
    "request": {"base_url": "https://api.partner.example", "path": "/v2/advisories"},
    "auth": {"type": "bearer"},
    "body": {
        "format": "json",
        "mapping": {
            "title": {"path": "bulletin.title"},
            "cves": {"path": "cves"},
            "source": {"const": "CERT"},
        },
    },
}


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _bulletin(database: Database, workspace: uuid.UUID, status: str) -> uuid.UUID:
    """A bulletin of the delivered generic template, with one revision."""
    version = (
        await _sql(
            database,
            "SELECT v.id FROM bulletin_template_versions v JOIN bulletin_templates t "
            "ON t.id = v.template_id WHERE t.workspace_id = $1 AND t.seed_key = 'generic_fr'",
            workspace,
        )
    )[0]["id"]
    bulletin, revision = uuid.uuid4(), uuid.uuid4()
    fields = {
        "title": "RCE dans Exemple",
        "summary": "Une faille.",
        "recommendations": "Mettre à jour.",
        "affected_products": [{"vendor": "exemple", "product": "serveur", "versions": "< 2"}],
        "references": [{"title": "Avis", "url": "https://exemple.org/avis"}],
    }
    await _sql(
        database,
        "INSERT INTO bulletins (id, workspace_id, ref, language, title, status, tlp, "
        "template_version_id, approved_at) VALUES ($1, $2, $3, 'fr', 'RCE', $4, 'GREEN', $5, "
        "now())",
        bulletin, workspace, f"CERT-2026-{uuid.uuid4().int % 10000:04d}", status, version,
    )  # fmt: skip
    await _sql(
        database,
        "INSERT INTO bulletin_revisions (id, workspace_id, bulletin_id, rev_no, fields, "
        "rendered_markdown, rendered_html, content_hash, created_by_type) "
        "VALUES ($1, $2, $3, 1, $4, '# RCE dans Exemple', '<h1>RCE</h1>', $5, 'user')",
        revision, workspace, bulletin, json.dumps(fields), "b" * 64,
    )  # fmt: skip
    await _sql(
        database, "UPDATE bulletins SET current_revision_id = $1 WHERE id = $2", revision, bulletin
    )
    return bulletin


class Client:
    def __init__(self, api: Api, csrf: str) -> None:
        self.api, self.h = api, {"x-csrf-token": csrf}

    async def call(self, method: str, path: str, body: Any = None, status: int = 200) -> Any:
        response = await self.api.client.request(
            method, self.api.url(path), json=body, headers=self.h
        )
        assert response.status_code == status, response.text
        return response.json() if response.content else None


async def _login(make_api: ApiFactory, user: SeededUser) -> Client:
    api = await make_api("backoffice")
    return Client(api, await sign_in(api, user))


async def test_publish_connector_api(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    async with harness(database, redis_url) as h:
        for slug in ("voc", "cert"):
            async with h.app_db(WORKSPACE_IDS[slug]) as db:
                await seed_templates(db, WORKSPACE_IDS[slug], slug, datetime.now(UTC))
                await db.commit()
    ana = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    a, e = await _login(make_api, ana), await _login(make_api, eve)
    base = "/workspaces/cert"

    # The authentication type decides which secrets are required.
    created = await e.call(
        "POST", f"{base}/connectors/publish",
        {"kind": "http_generic", "name": "Partenaire", "config": CONFIG}, 422,
    )  # fmt: skip
    assert created["detail"] == "missing_secret"
    secret = await e.call(
        "POST", f"{base}/secrets",
        {"name": "jeton-partenaire", "purpose": "connector", "value": "s3cr3t-value"}, 201,
    )  # fmt: skip
    connector = await e.call(
        "POST", f"{base}/connectors/publish",
        {"kind": "http_generic", "name": "Partenaire", "config": CONFIG,
         "secret_refs": {"credential": secret["id"]}}, 201,
    )  # fmt: skip
    assert connector["egress_domains"] == ["api.partner.example"]

    # Dry-run: only a validated bulletin, credentials masked, nothing sent.
    draft = await _bulletin(database, CERT, "draft")
    approved = await _bulletin(database, CERT, "approved")
    target = f"{base}/publish-targets/{connector['id']}/dry-run"
    refused = await e.call("POST", target, {"bulletin_id": str(draft)}, 422)
    assert refused["detail"] == "not_pushable"
    shown = await e.call("POST", target, {"bulletin_id": str(approved)})
    assert shown["url"] == "https://api.partner.example/v2/advisories"
    assert shown["headers"]["Authorization"] == "Bearer ••••••"
    assert json.loads(shown["body"]) == {"title": "RCE dans Exemple", "cves": [], "source": "CERT"}
    assert "s3cr3t" not in json.dumps(shown)

    # Mapping preview of an unsaved configuration: example data, then a real bulletin.
    preview = await e.call("POST", f"{base}/publish-mapping/preview", {"config": CONFIG})
    assert (preview["valid"], preview["sample"]) == (True, True)
    assert preview["payload"]["source"] == "CERT"
    assert "bulletin.fields.summary" in preview["paths"]
    broken = {**CONFIG, "body": {"format": "json", "mapping": {"x": {"path": "a["}}}}
    preview = await e.call(
        "POST", f"{base}/publish-mapping/preview", {"config": broken, "bulletin_id": str(approved)}
    )
    assert preview["valid"] is False
    assert {"loc": ["body", "mapping"], "path": "x", "code": "invalid_path"} in preview["errors"]

    # Exports: CSAF needs the workspace's publisher (Q42); drafts are never exported.
    export = f"{base}/bulletins/{approved}/export"
    missing = await e.call("GET", f"{export}?format=csaf", status=422)
    assert missing["detail"] == "csaf_publisher_missing"
    settings = await e.call("GET", f"{base}/bulletin-settings")
    await e.call(
        "PUT", f"{base}/bulletin-settings",
        {"ref_prefix": settings["ref_prefix"], "review_required": False,
         "default_template_id": settings["default_template_id"], "version": settings["version"],
         "csaf_publisher_name": "CERT Exemple",
         "csaf_publisher_namespace": "https://cert.example.org"},
    )  # fmt: skip
    response = await e.api.client.get(e.api.url(f"{export}?format=csaf"))
    assert response.status_code == 200, response.text
    assert "attachment" in response.headers["content-disposition"]
    csaf = response.json()
    assert csaf["document"]["publisher"]["name"] == "CERT Exemple"
    assert csaf["document"]["tracking"]["status"] == "interim"
    markdown = await e.api.client.get(e.api.url(f"{export}?format=markdown"))
    assert markdown.text == "# RCE dans Exemple"
    await e.call("GET", f"{base}/bulletins/{draft}/export?format=json", status=422)

    # A global connector (platform admins) is a target for every team (Q40).
    global_secret = await a.call(
        "POST", "/admin/secrets",
        {"name": "global-hook", "purpose": "connector", "value": "x-tok-123"}, 201,
    )  # fmt: skip
    shared = await a.call(
        "POST", "/admin/connectors/publish",
        {"kind": "http_generic", "name": "Plateforme commune", "config": CONFIG,
         "secret_refs": {"credential": global_secret["id"]}}, 201,
    )  # fmt: skip
    targets = await e.call("GET", f"{base}/publish-targets")
    assert {(t["name"], t["scope"]) for t in targets} == {
        ("Partenaire", "workspace"),
        ("Plateforme commune", "global"),
    }
    await e.call("POST", f"{base}/publish-targets/{shared['id']}/dry-run",
                 {"bulletin_id": str(approved)})  # fmt: skip
    # The VOC cannot use the CERT's connector.
    await a.call("POST", f"/workspaces/voc/publish-targets/{connector['id']}/dry-run",
                 {"bulletin_id": str(approved)}, 404)  # fmt: skip

    # Private range: requested by the team, decided by an administrator (Q41).
    network = f"{base}/connectors/publish/{connector['id']}/private-network"
    bad = await e.call("POST", network, {"cidrs": ["8.8.8.0/24"], "reason": "x"}, 422)
    assert bad["detail"] == "invalid_cidr"
    pending = await e.call(
        "POST", network, {"cidrs": ["10.20.0.0/16"], "reason": "Portail interne"}, 201
    )
    assert pending["status"] == "pending"
    await e.call("GET", "/admin/private-network-requests", status=403)
    queue = await a.call("GET", "/admin/private-network-requests")
    assert [(q["workspace_slug"], q["hosts"], q["cidrs"]) for q in queue] == [
        ("cert", ["api.partner.example"], ["10.20.0.0/16"])
    ]

    worker = create_engine(database.dsn("vv_worker", PASSWORDS.worker))

    async def ranges() -> list[str]:
        async with create_sessionmaker(worker)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(CERT,))
            row = await db.get(Connector, uuid.UUID(connector["id"]))
            assert row is not None
            return [str(n) for n in await approved_networks(db, row, tuple(row.egress_domains))]

    try:
        assert await ranges() == []  # nothing before the decision
        decided = await a.call(
            "POST", f"/admin/private-network-requests/{pending['id']}/decision",
            {"approve": True, "note": "Vu avec le RSSI"},
        )  # fmt: skip
        assert decided["status"] == "approved"
        assert await ranges() == ["10.20.0.0/16"]
        # Other ranges or another host: the approval no longer covers the connector.
        await e.call("POST", network, {"cidrs": ["10.30.0.0/16"], "reason": "Autre"}, 201)
        assert await ranges() == []
        history = await e.call("GET", network)
        assert [h["status"] for h in history] == ["pending", "approved"]
        await e.call("POST", network, {"cidrs": ["10.20.0.0/16"], "reason": "Retour"}, 201)
        assert await ranges() == ["10.20.0.0/16"]
        await a.call(
            "POST", f"/admin/private-network-requests/{pending['id']}/revoke", {"note": "Fin"}
        )
        assert await ranges() == []
    finally:
        await worker.dispose()

    audit = {
        r["action"]
        for r in await _sql(
            database, "SELECT action FROM audit_events WHERE action LIKE 'connector.%'"
        )
    }
    assert {
        "connector.created",
        "connector.private_network_requested",
        "connector.private_network_approved",
        "connector.private_network_revoked",
    } <= audit
