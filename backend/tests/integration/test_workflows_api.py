"""Workflow API: definitions, validation, versions, activation, runs (spec 02 §9)."""

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import httpx
import pytest
from pydantic import SecretStr

from app.ai.agents.presets import PRESETS
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context
from app.vault.service import Vault
from app.workflows.engine import ADVANCE_TASK
from app.workflows.seeds import seed_all
from app.workflows.webhooks import SIGNATURE_HEADER, TIMESTAMP_HEADER, WEBHOOK_TASK, receive, sign
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user

pytestmark = pytest.mark.integration


def _graph(*extra: dict[str, Any], edges: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "nodes": [
            {"id": "start", "type": "trigger.manual", "params": {}},
            {"id": "limit", "type": "transform.limit", "params": {"count": 5}},
            *extra,
        ],
        "edges": edges
        or [
            {
                "id": "e1",
                "from": {"node": "start", "port": "out"},
                "to": {"node": "limit", "port": "in"},
            }
        ],
    }


async def _rss_connector(database: Database, workspace: str) -> uuid.UUID:
    connector_id = uuid.uuid4()
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        await conn.execute(
            "INSERT INTO connectors (id, workspace_id, family, kind, name, config, egress_domains) "
            "VALUES ($1, $2, 'source', 'rss', 'CERT-FR', $3, ARRAY['www.cert.ssi.gouv.fr'])",
            connector_id,
            WORKSPACE_IDS[workspace],
            json.dumps({"allowed_domains": ["www.cert.ssi.gouv.fr"]}),
        )
    finally:
        await conn.close()
    return connector_id


async def _analyst(
    make_api: ApiFactory, database: Database, workspace: str, role: str = "analyst"
) -> tuple[Api, dict[str, str]]:
    user = await create_user(
        database.admin_dsn,
        f"{role}@{workspace}.example.com",
        workspaces={workspace: role},
        with_totp=True,
    )
    api = await make_api("backoffice")
    return api, {"x-csrf-token": await sign_in(api, user)}


async def test_node_types_expose_parameter_schemas(
    make_api: ApiFactory, database: Database
) -> None:
    api, _ = await _analyst(make_api, database, "voc")
    response = await api.client.get(api.url("/node-types"))
    assert response.status_code == 200
    types = {t["type"]: t for t in response.json()}
    assert {"trigger.cve_published", "vuln.scope_match", "notify.email"} <= set(types)
    assert not [t for t in types if t.startswith("test.")]
    assert types["vuln.scope_match"]["outputs"] == ["in_scope", "out_of_scope"]
    assert "condition" in types["transform.filter"]["params_schema"]["properties"]
    assert types["source.rss"]["queue"] == "collect"
    # Parameters pointing to a workspace object, for the editor's selectors.
    assert types["source.x"]["reference_fields"] == {
        "connector_id": {"kind": "connector", "family": "source", "connector_kinds": ["x_reader"]}
    }
    assert types["ai.agent"]["reference_fields"]["agent_id"]["kind"] == "agent"
    assert types["transform.filter"]["reference_fields"] == {}


async def test_workflow_lifecycle(make_api: ApiFactory, database: Database) -> None:
    api, h = await _analyst(make_api, database, "voc")
    base = api.url("/workspaces/voc/workflows")

    invalid = _graph(
        {"id": "bad", "type": "transform.filter", "params": {"condition": {"$expr": "json.["}}}
    )
    response = await api.client.post(base, json={"name": "W", "graph": invalid}, headers=h)
    assert response.status_code == 422
    codes = {(e["path"], e["code"]) for e in response.json()["errors"]}
    assert ("nodes.2", "unreachable_node") in codes
    assert any(path.startswith("nodes.2.params.condition") for path, _ in codes)

    response = await api.client.post(base, json={"name": "W", "graph": _graph()}, headers=h)
    assert response.status_code == 201, response.text
    workflow = response.json()
    assert workflow["latest_version_no"] == 1
    assert workflow["status"] == "draft"
    url = f"{base}/{workflow['id']}"

    assert (await api.client.post(base, json={"name": "W"}, headers=h)).status_code == 409

    stale = await api.client.post(
        f"{url}/versions", json={"graph": _graph(), "base_version_no": 0}, headers=h
    )
    assert stale.status_code == 409
    second = await api.client.post(
        f"{url}/versions",
        json={"graph": _graph(), "comment": "v2", "base_version_no": 1},
        headers=h,
    )
    assert second.status_code == 201
    assert second.json()["version_no"] == 2

    run = await api.client.post(f"{url}/runs", json={}, headers=h)
    assert run.status_code == 409  # not active yet

    activated = await api.client.post(f"{url}/versions/2/activate", headers=h)
    assert activated.status_code == 200, activated.text
    body = activated.json()
    assert body["status"] == "active"
    assert body["active_version_no"] == 2
    assert [(t["node_id"], t["type"], t["webhook_path"]) for t in body["triggers"]] == [
        ("start", "manual", None)
    ]
    assert body["webhook_secrets"] == []

    started = await api.client.post(
        f"{url}/runs", json={"input": {"a": 1}, "idempotency_key": "key-0001"}, headers=h
    )
    assert started.status_code == 202
    run_id = started.json()["run_id"]
    assert started.json()["created"] is True
    assert api.tasks.sent[-1] == (
        ADVANCE_TASK,
        {"run_id": run_id, "workspace_id": str(WORKSPACE_IDS["voc"])},
    )
    again = await api.client.post(
        f"{url}/runs", json={"input": {"a": 1}, "idempotency_key": "key-0001"}, headers=h
    )
    assert again.json() == {"run_id": run_id, "created": False}

    detail = await api.client.get(api.url(f"/workspaces/voc/runs/{run_id}"))
    assert detail.status_code == 200
    assert detail.json()["status"] == "queued"
    assert detail.json()["trigger_payload"] == {"a": 1}
    cancelled = await api.client.post(api.url(f"/workspaces/voc/runs/{run_id}/cancel"), headers=h)
    assert cancelled.status_code == 202
    assert (await api.client.get(f"{url}/runs")).json()[0]["id"] == run_id

    patched = await api.client.patch(url, json={"status": "paused", "version": 1}, headers=h)
    assert patched.status_code == 409
    current = (await api.client.get(url)).json()["version"]
    patched = await api.client.patch(url, json={"status": "paused", "version": current}, headers=h)
    assert patched.status_code == 200
    assert patched.json()["status"] == "paused"

    exported = await api.client.get(f"{url}/export")
    assert exported.status_code == 200
    copy = {**exported.json(), "name": "W (copie)"}
    imported = await api.client.post(
        api.url("/workspaces/voc/workflows/import"), json=copy, headers=h
    )
    assert imported.status_code == 201
    assert imported.json()["latest_graph"] == exported.json()["graph"]

    audit = await api.client.get(api.url("/workspaces/voc/audit"))
    actions = {e["action"] for e in audit.json()["items"]}
    assert {"workflow.created", "workflow.activated", "workflow.run_started"} <= actions


async def test_references_and_permissions_are_checked(
    make_api: ApiFactory, database: Database
) -> None:
    voc_connector = await _rss_connector(database, "voc")
    cert_api, cert_h = await _analyst(make_api, database, "cert")
    rss = {
        "id": "feed",
        "type": "source.rss",
        "params": {
            "connector_id": str(voc_connector),
            "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
        },
    }
    edges = [
        {
            "id": "e1",
            "from": {"node": "start", "port": "out"},
            "to": {"node": "limit", "port": "in"},
        },
        {
            "id": "e2",
            "from": {"node": "start", "port": "out"},
            "to": {"node": "feed", "port": "in"},
        },
    ]
    response = await cert_api.client.post(
        cert_api.url("/workspaces/cert/workflows"),
        json={"name": "Feed", "graph": _graph(rss, edges=edges)},
        headers=cert_h,
    )
    assert response.status_code == 422
    assert {"path": "nodes.2.params", "code": "connector_not_found"} in response.json()["errors"]

    voc_api, voc_h = await _analyst(make_api, database, "voc")
    response = await voc_api.client.post(
        voc_api.url("/workspaces/voc/workflows"),
        json={"name": "Feed", "graph": _graph(rss, edges=edges)},
        headers=voc_h,
    )
    assert response.status_code == 201, response.text
    workflow_id = response.json()["id"]
    hidden = await cert_api.client.get(cert_api.url(f"/workspaces/voc/workflows/{workflow_id}"))
    assert hidden.status_code == 404

    viewer_api, viewer_h = await _analyst(make_api, database, "voc", role="viewer")
    assert (
        await viewer_api.client.get(viewer_api.url(f"/workspaces/voc/workflows/{workflow_id}"))
    ).status_code == 200
    denied = await viewer_api.client.post(
        viewer_api.url("/workspaces/voc/workflows"), json={"name": "X"}, headers=viewer_h
    )
    assert denied.status_code == 403


async def _sql_admin(database: Database, query: str, *args: object) -> None:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        await conn.execute(query, *args)
    finally:
        await conn.close()


async def test_seed_workflows(make_api: ApiFactory, database: Database) -> None:
    settings = make_settings(database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)))
    first = await seed_all(settings, datetime.now(UTC))
    agents = [f"agent:{k}" for k in PRESETS]
    workflows = ["new_cve", "rewatch", "daily_watch"]
    templates = [f"template:{k}" for k in ("generic_fr", "generic_en", "urgent_fr")]
    delivered = [*agents, *workflows, *templates]
    assert first == {"voc": delivered, "cert": delivered}
    assert await seed_all(settings, datetime.now(UTC)) == {"voc": [], "cert": []}

    # A newer delivery reaches the workflows nobody edited, as an inactive version.
    await _sql_admin(
        database,
        "UPDATE workflow_versions SET graph_hash = 'old' FROM workflows w "
        "WHERE w.id = workflow_versions.workflow_id AND w.seed_key = 'rewatch'",
    )

    api, h = await _analyst(make_api, database, "cert")
    await _sql_admin(
        database,
        "UPDATE workflow_versions SET created_by = (SELECT id FROM users LIMIT 1) "
        "FROM workflows w WHERE w.id = workflow_versions.workflow_id "
        "AND w.seed_key = 'rewatch' AND w.workspace_id = $1",
        WORKSPACE_IDS["voc"],
    )
    refreshed = await seed_all(settings, datetime.now(UTC))
    assert refreshed == {"voc": [], "cert": ["rewatch"]}  # the VOC copy was edited
    workflows = (await api.client.get(api.url("/workspaces/cert/workflows"))).json()
    assert {w["seed_key"]: w["status"] for w in workflows} == {
        "new_cve": "draft",
        "rewatch": "draft",
        "daily_watch": "draft",
    }
    # Preset agents: local tools only are enabled; the others wait for a connector.
    listed = (await api.client.get(api.url("/workspaces/cert/agents"))).json()
    assert {a["preset"]: a["enabled"] for a in listed} == {
        "triage": True,
        "poc_hunter": False,
        "social": False,
        "forums": False,
        "vendor": False,
        "synthesis": True,
    }
    new_cve = next(w for w in workflows if w["seed_key"] == "new_cve")
    activated = await api.client.post(
        api.url(f"/workspaces/cert/workflows/{new_cve['id']}/versions/1/activate"), headers=h
    )
    assert activated.status_code == 200, activated.text
    assert {t["type"] for t in activated.json()["triggers"]} == {"cve_published", "cve_updated"}


async def test_signed_webhook(make_api: ApiFactory, database: Database) -> None:
    api, h = await _analyst(make_api, database, "voc")
    graph = {
        "schema_version": 1,
        "nodes": [
            {"id": "hook", "type": "trigger.webhook"},
            {"id": "limit", "type": "transform.limit", "params": {"count": 5}},
        ],
        "edges": [
            {
                "id": "e1",
                "from": {"node": "hook", "port": "out"},
                "to": {"node": "limit", "port": "in"},
            }
        ],
    }
    created = await api.client.post(
        api.url("/workspaces/voc/workflows"), json={"name": "Hook", "graph": graph}, headers=h
    )
    url = api.url(f"/workspaces/voc/workflows/{created.json()['id']}")
    activated = (await api.client.post(f"{url}/versions/1/activate", headers=h)).json()
    (secret,) = activated["webhook_secrets"]
    trigger_id = secret["trigger_id"]
    assert secret["webhook_path"] == f"/api/v1/hooks/{trigger_id}"
    # Re-activating keeps the URL and does not reveal the secret again.
    again = (await api.client.post(f"{url}/versions/1/activate", headers=h)).json()
    assert again["webhook_secrets"] == []
    assert again["triggers"][0]["id"] == trigger_id

    body = json.dumps({"cve_id": "CVE-2026-0001"}).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    # A server-to-server call: no Origin, no cookie.
    hook = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="https://backoffice.test"
    )
    unsigned = await hook.post(f"/api/v1/hooks/{trigger_id}", content=body)
    assert unsigned.status_code == 401
    stale = await hook.post(
        f"/api/v1/hooks/{trigger_id}",
        content=body,
        headers={
            TIMESTAMP_HEADER: "1000000000",
            SIGNATURE_HEADER: sign(secret["secret"], "1000000000", body),
        },
    )
    assert stale.status_code == 401
    api.tasks.sent.clear()
    for signature in (sign(secret["secret"], timestamp, body), "sha256=" + "0" * 64):
        accepted = await hook.post(
            f"/api/v1/hooks/{trigger_id}",
            content=body,
            headers={TIMESTAMP_HEADER: timestamp, SIGNATURE_HEADER: signature},
        )
        assert accepted.status_code == 202
    unknown = await hook.post(
        f"/api/v1/hooks/{uuid.uuid4()}",
        content=body,
        headers={TIMESTAMP_HEADER: timestamp, SIGNATURE_HEADER: "sha256=" + "0" * 64},
    )
    assert unknown.status_code == 202  # same answer: trigger ids cannot be probed
    await hook.aclose()

    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker))
    )
    engine = create_engine(settings.database_url_worker.get_secret_value())
    worker_vault = Vault(public_keys={}, keyrings=TEST_KEYRINGS)
    outcomes = []
    try:
        for name, kwargs in [*api.tasks.sent, api.tasks.sent[0]]:  # the first one replayed
            assert name == WEBHOOK_TASK
            async with create_sessionmaker(engine)() as db:
                init_context(db)
                outcomes.append(
                    await receive(
                        db,
                        worker_vault,
                        api.tasks,
                        trigger_id=uuid.UUID(kwargs["trigger_id"]),
                        timestamp=kwargs["timestamp"],
                        signature=kwargs["signature"],
                        body=base64.b64decode(kwargs["body"]),
                        now=datetime.now(UTC),
                    )
                )
    finally:
        await engine.dispose()
    assert outcomes == ["started", "bad_signature", "unknown_trigger", "ignored"]
    runs = (await api.client.get(f"{url}/runs")).json()
    assert len(runs) == 1
    assert runs[0]["trigger_type"] == "webhook"
