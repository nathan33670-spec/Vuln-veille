"""Exit criterion of phase 5 (PLAN.md), in a real browser against the real API.

An analyst edits the delivered « Nouvelle CVE NVD → investigation » workflow (adds an
agent, changes a filter), tests the filter on a catalogue CVE and publishes the new
version, entirely from the interface. The built back-office is served with the
production CSP; the workflow engine runs in-process on the queued tasks.

Needs a Chromium and the Playwright Node package, given by VV_E2E_CHROMIUM and
VV_E2E_PLAYWRIGHT, and the built front-end (pnpm --filter @vv/backoffice build);
skipped otherwise.
"""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest
from fastapi import FastAPI

from app.ai.agents.presets import seed_agents
from app.core.tasks import MemoryTaskQueue
from app.workflows.seeds import NEW_CVE
from tests.integration.browser import NEEDS_BROWSER, free_port, run_script, served
from tests.integration.conftest import Database
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import Harness, harness

SCRIPT = Path(__file__).with_name("phase5_exit.cjs")
VOC = WORKSPACE_IDS["voc"]
CVE = "CVE-2026-9001"
NAME = "Nouvelle CVE NVD → investigation"

pytestmark = [pytest.mark.integration, NEEDS_BROWSER]


async def _pump(api: FastAPI, engine: Harness) -> None:
    """The workers: tasks queued by the API run in-process, in order."""
    queue: MemoryTaskQueue = api.state.tasks
    while True:
        if queue.sent:
            engine.tasks.sent.extend(queue.sent)
            queue.sent.clear()
            await engine.drain()
        await asyncio.sleep(0.2)


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def test_phase_5_exit_in_a_browser(
    database: Database, redis_url: str, clean_state: None, tmp_path: Path
) -> None:
    user = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, base_score, severity, kev, "
        "first_seen_at, synced_at) VALUES ($1, 'RCE', 9.8, 'CRITICAL', NULL, now(), now())",
        CVE,
    )
    port = free_port()
    async with harness(database, redis_url) as engine:
        async with engine.app_db(VOC) as db:
            await seed_agents(db, VOC, datetime.now(UTC))
            await db.commit()
        workflow_id = await engine.workflow(VOC, NAME, NEW_CVE)
        async with served(database, redis_url, port) as api:
            pump = asyncio.create_task(_pump(api, engine))
            code, report = await run_script(
                str(SCRIPT),
                {
                    "base": f"http://localhost:{port}",
                    "email": user.email,
                    "password": user.password,
                    "totpSecret": user.totp_secret,
                    "workflow": NAME,
                    "cve": CVE,
                    "artifacts": str(tmp_path),
                },
            )
            pump.cancel()
    assert code == 0, report

    # The new version holds the added agent and the changed filter; the draft is gone.
    versions = await _sql(
        database,
        "SELECT version_no, graph, comment FROM workflow_versions WHERE workflow_id = $1 "
        "ORDER BY version_no",
        workflow_id,
    )
    assert [v["version_no"] for v in versions] == [1, 2], report
    graph = json.loads(versions[1]["graph"])
    nodes = {n["id"]: n for n in graph["nodes"]}
    added = [n for n in graph["nodes"] if n["id"] not in {x["id"] for x in NEW_CVE["nodes"]}]
    assert [n["type"] for n in added] == ["ai.agent"]
    assert added[0]["params"]["agent_id"]
    assert {
        "from": {"node": "attach", "port": "out"},
        "to": {"node": added[0]["id"], "port": "in"},
    } in [{"from": e["from"], "to": e["to"]} for e in graph["edges"]]
    assert "json.base_score" in nodes["urgent"]["params"]["condition"]["$expr"]
    assert versions[1]["comment"] == "Agent forums sur les avis et seuil CVSS"
    assert await _sql(database, "SELECT 1 FROM workflow_drafts") == []
    # The filter was tested on the CVE, alone, before publication.
    tests = await _sql(
        database,
        "SELECT test_node_id, status FROM workflow_runs WHERE mode = 'test' ORDER BY queued_at",
    )
    assert [(t["test_node_id"], t["status"]) for t in tests] == [("urgent", "succeeded")]
