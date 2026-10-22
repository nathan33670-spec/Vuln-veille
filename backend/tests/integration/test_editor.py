"""Visual editor support (phase 5): server-side drafts with concurrent edit detection,
a node tested alone on pinned inputs (dry-run, no data left behind), run events."""

import json
import uuid
from typing import Any

import asyncpg
import pytest

from tests.integration.conftest import Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user
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
        run_ids: dict[str, str] = {}
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
            run_id = run_ids[node_id] = started.json()["run_id"]
            run = (await api.client.get(api.url(f"/workspaces/voc/runs/{run_id}"))).json()
            assert run["status"] == "succeeded", run
            assert [n["node_id"] for n in run["node_runs"]] == [node_id]  # that node only
            assert (run["mode"], run["test_node_id"]) == ("test", node_id)
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

    # Past outputs of a node, reusable as pinned data downstream.
    outputs = (await api.client.get(api.url(f"{base}/nodes/high/outputs"))).json()
    assert [(o["run_id"], o["mode"], o["output_count"]) for o in outputs] == [
        (run_ids["high"], "test", 1)
    ]

    # AI engine calls made by a node are counted on it, with their estimated cost.
    node_run_id = (
        await _sql(
            database, "SELECT id FROM node_runs WHERE run_id = $1", uuid.UUID(run_ids["upsert"])
        )
    )[0]["id"]
    await _sql(
        database,
        "INSERT INTO agent_runs (id, workspace_id, task, spec, context_type, context_id, input, "
        "status, turns, tool_calls, input_tokens, output_tokens, cache_read_tokens, "
        "cache_write_tokens, cost_estimate_usd, sources, injection_flags, queued_at) "
        "VALUES ($1, $2, 'ai.summarize', '{}', 'node_run', $3, '{}', 'succeeded', 1, 0, 10, 5, "
        "0, 0, 0.012, '[]', '[]', now())",
        uuid.uuid4(),
        WORKSPACE_IDS["voc"],
        str(node_run_id),
    )
    detail = (await api.client.get(api.url(f"/workspaces/voc/runs/{run_ids['upsert']}"))).json()
    assert (detail["node_runs"][0]["ai_calls"], detail["node_runs"][0]["ai_cost_usd"]) == (
        1,
        "0.012000",
    )


async def test_expression_preview_and_samples(make_api: ApiFactory, database: Database) -> None:
    analyst = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    viewer = await create_user(
        database.admin_dsn, "view@voc.example.com", workspaces={"voc": "viewer"}, with_totp=True
    )
    api: Api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, analyst)}
    preview = api.url("/workspaces/voc/workflows/preview-expression")
    item = {"json": {"score": 9.8, "cve_id": CVE, "text": "{{ 7 * 7 }}"}, "meta": {"trust": "x"}}

    async def evaluate(body: dict[str, Any]) -> dict[str, Any]:
        response = await api.client.post(preview, json=body, headers=h)
        assert response.status_code == 200, response.text
        return dict(response.json())

    assert (await evaluate({"expr": "json.score >= `7`", "item": item}))["value"] is True
    assert (await evaluate({"expr": "json.[", "item": item}))["error"].startswith(
        "invalid expression"
    )
    rendered = await evaluate({"tpl": "{{ json.cve_id }} : {{ json.text }}", "item": item})
    assert rendered["value"] == f"{CVE} : {{{{ 7 * 7 }}}}"  # item data is never compiled
    bad = await api.client.post(preview, json={"expr": "a", "tpl": "b"}, headers=h)
    assert bad.status_code == 422

    # A real catalogue CVE, as the NVD event or as the CVE record.
    assert (
        await api.client.get(api.url(f"/workspaces/voc/workflow-samples/cve/{CVE}"))
    ).status_code == 404
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, base_score, severity, first_seen_at, "
        "synced_at) VALUES ($1, 'RCE', 9.8, 'CRITICAL', now(), now())",
        CVE,
    )
    sample = (
        await api.client.get(api.url(f"/workspaces/voc/workflow-samples/cve/{CVE.lower()}"))
    ).json()
    assert sample["event"] == {
        "cve_id": CVE,
        "change_types": ["published"],
        "source": "nvd",
        "severity": "CRITICAL",
        "base_score": 9.8,
    }
    assert sample["summary"]["description"] == "RCE"

    # Both are editor tools.
    await api.client.post(api.url("/auth/logout"), headers=h)
    hv = {"x-csrf-token": await sign_in(api, viewer)}
    denied = await api.client.post(preview, json={"expr": "json", "item": item}, headers=hv)
    assert denied.status_code == 403
    sample_denied = await api.client.get(api.url(f"/workspaces/voc/workflow-samples/cve/{CVE}"))
    assert sample_denied.status_code == 403


async def test_restore_and_export_a_version(make_api: ApiFactory, database: Database) -> None:
    user = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api: Api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, user)}
    first = _graph()
    created = await api.client.post(
        api.url("/workspaces/voc/workflows"), json={"name": "Versions", "graph": first}, headers=h
    )
    base = f"/workspaces/voc/workflows/{created.json()['id']}"
    second = _graph({"id": "cap", "type": "transform.limit", "params": {"count": 3}})
    second["edges"].append(
        {"id": "e4", "from": {"node": "notify", "port": "out"}, "to": {"node": "cap", "port": "in"}}
    )
    v2 = await api.client.post(
        api.url(f"{base}/versions"), json={"graph": second, "base_version_no": 1}, headers=h
    )
    assert v2.status_code == 201, v2.text

    # Restoring creates a new version from the old graph; history is kept.
    stale = await api.client.post(
        api.url(f"{base}/versions/1/restore"), json={"base_version_no": 1}, headers=h
    )
    assert stale.status_code == 409
    restored = await api.client.post(
        api.url(f"{base}/versions/1/restore"), json={"base_version_no": 2}, headers=h
    )
    assert restored.status_code == 201, restored.text
    assert restored.json()["version_no"] == 3
    assert restored.json()["comment"] == "Restauration de la v1"
    assert [n["id"] for n in restored.json()["graph"]["nodes"]] == [n["id"] for n in first["nodes"]]
    audit = await _sql(
        database,
        "SELECT details FROM audit_events WHERE action = 'workflow.version_restored'",
    )
    assert json.loads(audit[0]["details"])["restored_from"] == 1

    # Any version exports in the import format.
    exported = (await api.client.get(api.url(f"{base}/export?version_no=2"))).json()
    assert exported["format"] == "vuln-veille.workflow/1"
    assert "cap" in {n["id"] for n in exported["graph"]["nodes"]}
    missing = await api.client.get(api.url(f"{base}/export?version_no=9"))
    assert missing.status_code == 404
