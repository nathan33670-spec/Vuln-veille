"""Pushes (phase 7, 7B): « Pousser » with a second factor at the first push only (Q43),
the ``publish`` worker sending through the connector's credentials, the journal of
every attempt redacted, create then update with the remote id, retries with backoff,
refusals, the connection test on the example bulletin, and the ``publish.api`` node
behind an approval."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy import select

from app.core.db import create_engine, create_sessionmaker
from app.core.tasks import MemoryTaskQueue
from app.publish.runner import PUSH_TASK, PushDeps, run_push
from app.vault.service import Vault
from app.workflows.engine import advance_task, decide_approval
from app.workflows.models import NodeRun, WorkflowRun
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.conftest import PASSWORDS, ApiFactory, Database
from tests.integration.publish_support import (
    Client,
    login,
    seed_all_templates,
    sql,
    validated_bulletin,
)
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import harness
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]
BASE = "https://api.partner.example"
SECRET = "s3cr3t-value-42"
CONFIG: dict[str, Any] = {
    "request": {
        "base_url": BASE,
        "path": "/v2/advisories",
        "update": {"method": "PUT", "path": "/v2/advisories/{{ remote_id }}"},
    },
    "auth": {"type": "bearer"},
    "body": {
        "format": "json",
        "mapping": {"title": {"path": "bulletin.title"}, "ref": {"path": "bulletin.ref"}},
    },
    "response": {"remote_id_path": "data.id"},
    "retry": {"max_attempts": 2, "backoff_seconds": [30]},
}


class Partner(FakeWeb):
    """The remote API: answers by method and path, echoes the token back (to check it
    never reaches the journal), and can fail on demand."""

    def __init__(self) -> None:
        super().__init__()
        self.failures: list[int] = []
        self.received: list[tuple[str, str, dict[str, str], Any]] = []
        self.routes[f"{BASE}/v2/advisories"] = self._create
        self.routes[f"{BASE}/v2/advisories/ADV-1"] = self._update

    def _record(self, request: httpx.Request) -> int | None:
        body = json.loads(request.content) if request.content else None
        self.received.append((request.method, request.url.path, dict(request.headers), body))
        return self.failures.pop(0) if self.failures else None

    def _create(self, request: httpx.Request) -> tuple[Any, ...]:
        failure = self._record(request)
        if failure:
            return failure, {"error": "unavailable"}
        echoed = request.headers.get("authorization", "")
        return 201, {"data": {"id": "ADV-1", "echo": echoed}}

    def _update(self, request: httpx.Request) -> tuple[Any, ...]:
        failure = self._record(request)
        return (failure, {"error": "x"}) if failure else (200, {"data": {"id": "ADV-1"}})


async def _connector(e: Client) -> str:
    secret = await e.call(
        "POST", "/workspaces/cert/secrets",
        {"name": "partner-token", "purpose": "connector", "value": SECRET}, 201,
    )  # fmt: skip
    connector = await e.call(
        "POST", "/workspaces/cert/connectors/publish",
        {"kind": "http_generic", "name": "Partenaire", "config": CONFIG,
         "secret_refs": {"credential": secret["id"]}}, 201,
    )  # fmt: skip
    return str(connector["id"])


async def test_push_journal_and_retries(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    e = await login(make_api, eve)
    connector_id = await _connector(e)
    bulletin = await validated_bulletin(database, CERT, "approved")
    draft = await validated_bulletin(database, CERT, "draft")
    partner = Partner()
    queue = MemoryTaskQueue()
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    deps = PushDeps(
        make_settings(redis_url=SecretStr(redis_url)),
        Vault(public_keys={}, keyrings=TEST_KEYRINGS),
        queue,
        http=partner.client("api.partner.example"),
    )
    base = "/workspaces/cert"

    async def work(push_id: str) -> dict[str, Any]:
        name, kwargs = e.api.tasks.sent.pop() if e.api.tasks.sent else queue.sent.pop()
        assert (name, kwargs["publication_id"]) == (PUSH_TASK, push_id)
        await run_push(create_sessionmaker(engine), deps, uuid.UUID(push_id), CERT)
        return dict(await e.call("GET", f"{base}/publications/{push_id}"))

    try:
        # Only a validated bulletin; the first push needs a recent second factor.
        refused = await e.call(
            "POST", f"{base}/bulletins/{draft}/push", {"connector_id": connector_id}, 422
        )
        assert refused["detail"] == "not_pushable"
        await sql(database, "UPDATE sessions SET step_up_at = now() - interval '1 hour'")
        stale = await e.call(
            "POST", f"{base}/bulletins/{bulletin}/push", {"connector_id": connector_id}, 403
        )
        assert stale["detail"] == "step_up_required"
        await sql(database, "UPDATE sessions SET step_up_at = now()")
        queued = await e.call(
            "POST", f"{base}/bulletins/{bulletin}/push", {"connector_id": connector_id}, 202
        )
        assert queued["status"] == "queued"
        await e.call(
            "POST", f"{base}/bulletins/{bulletin}/push", {"connector_id": connector_id}, 409
        )  # already in flight

        done = await work(queued["id"])
        assert (done["status"], done["mode"], done["remote_id"]) == ("succeeded", "create", "ADV-1")
        method, path, headers, body = partner.received[-1]
        assert (method, path) == ("POST", "/v2/advisories")
        assert headers["authorization"] == f"Bearer {SECRET}"
        assert headers["idempotency-key"]
        assert body == {"title": "RCE dans Exemple", "ref": body["ref"]}
        # The journal never holds the credential, even echoed back by the remote API.
        attempt = done["attempt_log"][0]
        assert attempt["request"]["headers"]["Authorization"] == "Bearer ••••••"
        assert attempt["response_status"] == 201
        assert SECRET not in json.dumps(done)

        # Next push: an update of the remote advisory, no second factor asked (Q43).
        await sql(database, "UPDATE sessions SET step_up_at = now() - interval '1 hour'")
        partner.failures = [503]
        again = await e.call(
            "POST", f"{base}/bulletins/{bulletin}/push", {"connector_id": connector_id}, 202
        )
        retried = await work(again["id"])
        assert (retried["status"], retried["error"], retried["attempts"]) == (
            "retrying", "http_503", 1,
        )  # fmt: skip
        done = await work(again["id"])  # the retry, queued with its backoff
        assert (done["status"], done["mode"], done["attempts"]) == ("succeeded", "update", 2)
        assert [r[:2] for r in partner.received[-2:]] == [
            ("PUT", "/v2/advisories/ADV-1"),
            ("PUT", "/v2/advisories/ADV-1"),
        ]

        # A client error is not retried; the journal lists every push of the bulletin.
        partner.failures = [400]
        failing = await e.call(
            "POST", f"{base}/bulletins/{bulletin}/push", {"connector_id": connector_id}, 202
        )
        failed = await work(failing["id"])
        assert (failed["status"], failed["error"]) == ("failed", "http_400")
        history = await e.call("GET", f"{base}/publications?bulletin_id={bulletin}")
        assert [h["status"] for h in history] == ["failed", "succeeded", "succeeded"]

        # Connection test: the example bulletin, marked as a test.
        test = await e.call("POST", f"{base}/publish-targets/{connector_id}/test", None, 202)
        tested = await work(test["id"])
        assert (tested["status"], tested["is_test"]) == ("succeeded", True)
        assert partner.received[-1][3]["title"].startswith("[TEST]")
    finally:
        await engine.dispose()
    audit = {r["action"] for r in await sql(database, "SELECT action FROM audit_events")}
    assert {"bulletin.pushed", "connector.test_pushed"} <= audit


def _graph(connector_id: str, *, guarded: bool) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [
        {"id": "start", "type": "trigger.manual"},
        {"id": "push", "type": "publish.api", "params": {"connector_id": connector_id}},
    ]
    edges = [{"id": "e1", "from": {"node": "start", "port": "out"},
              "to": {"node": "push", "port": "in"}}]  # fmt: skip
    if guarded:
        nodes.insert(1, {"id": "approve", "type": "control.approval"})
        edges = [
            {"id": "e1", "from": {"node": "start", "port": "out"},
             "to": {"node": "approve", "port": "in"}},
            {"id": "e2", "from": {"node": "approve", "port": "approved"},
             "to": {"node": "push", "port": "in"}},
        ]  # fmt: skip
    return {"schema_version": 1, "nodes": nodes, "edges": edges}


async def test_publish_node_behind_an_approval(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    e = await login(make_api, eve)
    connector_id = await _connector(e)
    bulletin = await validated_bulletin(database, CERT, "approved")

    # Without an approval upstream, the graph is refused.
    unguarded = await e.call(
        "POST", "/workspaces/cert/workflows",
        {"name": "Push direct", "graph": _graph(connector_id, guarded=False)}, 422,
    )  # fmt: skip
    assert "approval_required_upstream" in json.dumps(unguarded)

    async with harness(database, redis_url) as h:
        workflow_id = await h.workflow(CERT, "Push", _graph(connector_id, guarded=True))
        run_id = await h.manual(CERT, workflow_id, {"bulletin": {"id": str(bulletin)}})
        await h.drain()
        assert h.others == []  # nothing pushed before the decision
        async with h.app_db(CERT) as db:
            run = await db.get(WorkflowRun, run_id)
            assert run is not None
            assert await decide_approval(
                db, run, "approve", approved=True, actor=eve.id, comment="ok",
                now=datetime.now(UTC),
            )  # fmt: skip
            await db.commit()
        advance_task(h.tasks, run_id, CERT)
        await h.drain()
        assert [name for name, _ in h.others] == [PUSH_TASK]
        async with h.app_db(CERT) as db:
            rows = await db.execute(
                select(NodeRun).where(NodeRun.run_id == run_id, NodeRun.node_id == "push")
            )
            node = rows.scalars().one()
            assert node.output["out"][0]["json"]["publication"]["status"] == "queued"
    pushes = await sql(database, "SELECT origin, status FROM publications")
    assert [(p["origin"], p["status"]) for p in pushes] == [("workflow", "queued")]


async def test_rate_limit_delays_without_spending_an_attempt(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    e = await login(make_api, eve)
    connector_id = await _connector(e)
    connector = await e.call("GET", f"/workspaces/cert/connectors/publish/{connector_id}")
    await e.call(
        "PATCH", f"/workspaces/cert/connectors/publish/{connector_id}",
        {"version": connector["version"], "config": {**CONFIG, "rate_limit_per_minute": 1}},
    )  # fmt: skip
    first = await validated_bulletin(database, CERT, "approved")
    second = await validated_bulletin(database, CERT, "approved")
    queue = MemoryTaskQueue()
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    redis = Redis.from_url(redis_url)
    deps = PushDeps(
        make_settings(redis_url=SecretStr(redis_url)),
        Vault(public_keys={}, keyrings=TEST_KEYRINGS),
        queue,
        redis=redis,
        http=Partner().client("api.partner.example"),
    )
    try:
        ids = []
        for bulletin in (first, second):
            pushed = await e.call(
                "POST", f"/workspaces/cert/bulletins/{bulletin}/push",
                {"connector_id": connector_id}, 202,
            )  # fmt: skip
            ids.append(pushed["id"])
        for push_id in ids:
            await run_push(create_sessionmaker(engine), deps, uuid.UUID(push_id), CERT)
        rows = {
            str(r["id"]): r
            for r in await sql(database, "SELECT id, status, attempts, error FROM publications")
        }
        assert (rows[ids[0]]["status"], rows[ids[0]]["attempts"]) == ("succeeded", 1)
        delayed = rows[ids[1]]
        assert (delayed["status"], delayed["attempts"], delayed["error"]) == (
            "retrying", 0, "rate_limited",
        )  # fmt: skip
        assert [name for name, _ in queue.sent] == [PUSH_TASK]  # retried after a minute
    finally:
        await redis.aclose()
        await engine.dispose()
