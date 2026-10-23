"""Publication connectors, API side (phase 7, 7A): configuration checked by
authentication type, masked dry-run on a validated bulletin, mapping preview, exports
(CSAF, JSON, Markdown), global targets, and the administrators' approval of a private
range, applied by the worker only while it matches the connector (ADR-030)."""

import json
import uuid
from typing import Any

import pytest

from app.connectors.models import Connector
from app.connectors.runtime import approved_networks
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from tests.integration.conftest import PASSWORDS, ApiFactory, Database
from tests.integration.publish_support import (
    login,
    seed_all_templates,
    sql,
    validated_bulletin,
)
from tests.integration.seed import WORKSPACE_IDS, create_user

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


async def test_publish_connector_api(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    ana = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    a, e = await login(make_api, ana), await login(make_api, eve)
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
    draft = await validated_bulletin(database, CERT, "draft")
    approved = await validated_bulletin(database, CERT, "approved")
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
        for r in await sql(
            database, "SELECT action FROM audit_events WHERE action LIKE 'connector.%'"
        )
    }
    assert {
        "connector.created",
        "connector.private_network_requested",
        "connector.private_network_approved",
        "connector.private_network_revoked",
    } <= audit
