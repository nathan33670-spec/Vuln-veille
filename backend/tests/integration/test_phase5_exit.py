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
import os
import shutil
import socket
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncpg
import pytest
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr
from starlette.responses import FileResponse

from app.ai.agents.presets import seed_agents
from app.app_factory import create_app
from app.core.mailer import MemoryMailer
from app.core.tasks import MemoryTaskQueue
from app.workflows.seeds import NEW_CVE
from tests.conftest import make_settings
from tests.integration.conftest import BACKEND_DIR, PASSWORDS, Database
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import Harness, harness

CHROMIUM = os.environ.get("VV_E2E_CHROMIUM", "")
PLAYWRIGHT = os.environ.get("VV_E2E_PLAYWRIGHT", "")
DIST = BACKEND_DIR.parent / "frontend" / "apps" / "backoffice" / "dist"
SCRIPT = Path(__file__).with_name("phase5_exit.cjs")
# The production policy (deploy/caddy/Caddyfile), without upgrade-insecure-requests.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; "
    "trusted-types dompurify"
)
VOC = WORKSPACE_IDS["voc"]
CVE = "CVE-2026-9001"
NAME = "Nouvelle CVE NVD → investigation"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (CHROMIUM and PLAYWRIGHT and shutil.which("node") and (DIST / "index.html").exists()),
        reason="browser test: set VV_E2E_CHROMIUM, VV_E2E_PLAYWRIGHT and build the back-office",
    ),
]

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def _site(api: FastAPI) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """The API under /api, the built single-page app elsewhere, with the CSP."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        if scope["path"].startswith("/api/"):
            await api(scope, receive, send)
            return
        relative = scope["path"].lstrip("/")
        target = (DIST / relative).resolve()
        if not relative or not target.is_file() or DIST.resolve() not in target.parents:
            target = DIST / "index.html"

        async def with_csp(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [
                    *message.get("headers", []),
                    (b"content-security-policy", CSP.encode()),
                ]
            await send(message)

        await FileResponse(target)(scope, receive, with_csp)

    return app


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@asynccontextmanager
async def _served(database: Database, redis_url: str, port: int) -> AsyncIterator[FastAPI]:
    settings = make_settings(
        database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
        database_url_portal=SecretStr(database.dsn("vv_portal", PASSWORDS.portal)),
        redis_url=SecretStr(redis_url),
        backoffice_origin=f"http://localhost:{port}",
        portal_origin="http://localhost:1",
    )
    api = create_app("backoffice", settings, mailer=MemoryMailer(), tasks=MemoryTaskQueue())
    async with api.router.lifespan_context(api):
        config = uvicorn.Config(
            _site(api), host="127.0.0.1", port=port, lifespan="off", log_level="warning"
        )
        server = uvicorn.Server(config)
        serving = asyncio.create_task(server.serve())
        while not server.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an event
            await asyncio.sleep(0.05)
        try:
            yield api
        finally:
            server.should_exit = True
            await serving


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
    port = _free_port()
    async with harness(database, redis_url) as engine:
        async with engine.app_db(VOC) as db:
            await seed_agents(db, VOC, datetime.now(UTC))
            await db.commit()
        workflow_id = await engine.workflow(VOC, NAME, NEW_CVE)
        async with _served(database, redis_url, port) as api:
            pump = asyncio.create_task(_pump(api, engine))
            config = {
                "base": f"http://localhost:{port}",
                "email": user.email,
                "password": user.password,
                "totpSecret": user.totp_secret,
                "workflow": NAME,
                "cve": CVE,
                "chromium": CHROMIUM,
                "playwright": PLAYWRIGHT,
                "artifacts": str(tmp_path),
            }
            browser = await asyncio.create_subprocess_exec(
                "node",
                str(SCRIPT),
                json.dumps(config),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output, _ = await asyncio.wait_for(browser.communicate(), timeout=240)
            pump.cancel()
    report = output.decode()
    assert browser.returncode == 0, report

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
