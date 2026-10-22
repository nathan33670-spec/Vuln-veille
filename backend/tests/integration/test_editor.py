"""Visual editor support (phase 5): server-side drafts with concurrent edit detection,
a node tested alone on pinned inputs (dry-run, no data left behind), run events."""

import json
from typing import Any

import asyncpg
import pytest

from tests.integration.conftest import Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import create_user
from tests.integration.workflow_harness import harness

pytestmark = pytest.mark.integration

CVE = "CVE-2026-8001"


def _graph(*extra: dict[str, Any]) -> dict[str, Any]:
    nodes = [
        {"id": "start", "type": "trigger.manual", "params": {}},
        {
            "id": "high",
            "type": "transform.filter",
            "params": {"condition": {"$expr": "json.score >= `7`"}},
        },
        {"id": "upsert", "type": "vuln.upsert", "params": {}},
        {"id": "notify", "type": "notify.email", "params": {}},
        *extra,
    ]
    edges = [
        {
            "id": "e1",
            "from": {"node": "start", "port": "out"},
            "to": {"node": "high", "port": "in"},
        },
        {
            "id": "e2",
            "from": {"node": "high", "port": "out"},
            "to": {"node": "upsert", "port": "in"},
        },
        {
            "id": "e3",
            "from": {"node": "upsert", "port": "out"},
            "to": {"node": "notify", "port": "in"},
        },
    ]
    return {"schema_version": 1, "nodes": nodes, "edges": edges}


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def test_drafts_test_node_and_events(
    make_api: ApiFactory, database: Database, redis_url: str
) -> None:
    user = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api: Api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, user)}
    created = await api.client.post(
        api.url("/workspaces/voc/workflows"),
        json={"name": "Éditeur", "graph": _graph()},
        headers=h,
    )
    assert created.status_code == 201, created.text
    workflow = created.json()
    base = f"/workspaces/voc/workflows/{workflow['id']}"

    # Draft: kept as typed, with its validation errors; stale once a version is published.
    assert (await api.client.get(api.url(f"{base}/draft"))).status_code == 404
    broken = _graph({"id": "bad", "type": "transform.limit", "params": {"count": 0}})
    saved = await api.client.put(
        api.url(f"{base}/draft"), json={"graph": broken, "base_version_no": 1}, headers=h
    )
    assert saved.status_code == 200, saved.text
    draft = saved.json()
    assert draft["stale"] is False
    assert {"path": "nodes.4.params.count", "code": "greater_than_equal"} in draft["errors"]
    published = await api.client.post(
        api.url(f"{base}/versions"), json={"graph": _graph(), "base_version_no": 1}, headers=h
    )
    assert published.status_code == 201, published.text
    stale = (await api.client.get(api.url(f"{base}/draft"))).json()
    assert stale["stale"] is True
    assert stale["latest_version_no"] == 2

    # An invalid graph cannot be tested.
    refused = await api.client.post(
        api.url(f"{base}/test-node"), json={"node_id": "high"}, headers=h
    )
    assert refused.status_code == 422
    assert refused.json()["detail"] == "invalid_graph"
    assert (await api.client.delete(api.url(f"{base}/draft"), headers=h)).status_code == 204

    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, first_seen_at, synced_at) "
        "VALUES ($1, 'RCE', now(), now())",
        CVE,
    )
    pinned = {"in": [{"json": {"cve_id": CVE, "score": 9.8}}, {"json": {"score": 3}}]}
    async with harness(database, redis_url) as engine:
        results: dict[str, Any] = {}
        for node_id in ("high", "upsert", "notify"):
            started = await api.client.post(
                api.url(f"{base}/test-node"),
                json={"node_id": node_id, "inputs": pinned},
                headers=h,
            )
            assert started.status_code == 202, started.text
            engine.tasks.sent.extend(api.tasks.sent)
            api.tasks.sent.clear()
            await engine.drain()
            run_id = started.json()["run_id"]
            run = (await api.client.get(api.url(f"/workspaces/voc/runs/{run_id}"))).json()
            assert run["status"] == "succeeded", run
            assert [n["node_id"] for n in run["node_runs"]] == [node_id]  # that node only
            node = (
                await api.client.get(api.url(f"/workspaces/voc/runs/{run_id}/nodes/{node_id}"))
            ).json()
            results[node_id] = node
        engine_mails = engine.mails

    # The filter ran on the pinned items, marked as pinned data.
    kept = results["high"]["output"]["out"]
    assert [i["json"]["score"] for i in kept] == [9.8]
    assert kept[0]["meta"]["source"] == "pinned"
    # vuln.upsert showed what it would do, and left nothing behind.
    assert results["upsert"]["output"]["out"][0]["json"]["created"] is True
    assert await _sql(database, "SELECT id FROM vulnerabilities") == []
    # notify.email is an output node: dry-run, no mail.
    assert engine_mails == []
    assert any(log.get("dry_run") for log in results["notify"]["logs"])

    # Test runs stay out of the run history.
    runs = (await api.client.get(api.url(f"{base}/runs"))).json()
    assert runs == []
    listed = (await api.client.get(api.url("/workspaces/voc/workflows"))).json()
    assert listed[0]["last_run"] is None

    # Run events: node states then the run's, as server-sent events.
    response = await api.client.get(api.url(f"/workspaces/voc/runs/{run_id}/events"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    events = [
        (block.split("\n")[0].removeprefix("event: "), json.loads(block.split("\n")[1][6:]))
        for block in response.text.strip().split("\n\n")
    ]
    assert events[0][0] == "node"
    assert events[0][1]["node_id"] == "notify"
    assert events[-1] == ("run", {"status": "succeeded", "error": None})
