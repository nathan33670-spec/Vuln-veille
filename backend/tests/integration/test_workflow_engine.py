"""Workflow engine against PostgreSQL: dispatch, execution, retries, recovery (spec 02 §5)."""

import json
import uuid
from datetime import timedelta
from itertools import pairwise
from typing import Any, ClassVar

import asyncpg
import pytest
from sqlalchemy import select

from app.workflows.base import (
    NodeCategory,
    NodeContext,
    NodeError,
    NodeParams,
    NodeType,
    Outputs,
    register_node,
)
from app.workflows.engine import Limits, decide_approval
from app.workflows.models import NodeRun, WorkflowRun
from app.workflows.seeds import _edge, _node
from tests.integration.conftest import Database
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import Harness, harness
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

VOC, CERT = WORKSPACE_IDS["voc"], WORKSPACE_IDS["cert"]
LOG4J_CPE = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
FAILURES: dict[str, int] = {}


class FlakyParams(NodeParams):
    key: str
    failures: int = 0


@register_node
class Flaky(NodeType):
    """Test node: fails ``failures`` times, then passes its items through."""

    type = "test.flaky"
    label = "Flaky"
    category = NodeCategory.TRANSFORM
    Params = FlakyParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        assert isinstance(params, FlakyParams)
        FAILURES[params.key] = FAILURES.get(params.key, 0) + 1
        if FAILURES[params.key] <= params.failures:
            raise NodeError("flaky")
        return {"out": inputs.get("in", [])}


class SinkParams(NodeParams):
    pass


@register_node
class Sink(NodeType):
    """Test node with an external effect: must be guarded by an approval."""

    type = "test.sink"
    label = "Sink"
    category = NodeCategory.OUTPUT
    Params = SinkParams
    requires_approval_upstream: ClassVar[bool] = True

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        return {"out": inputs.get("in", [])}


# The phase 3 delivery of "Nouvelle CVE NVD" (no AI): the exit criterion of phase 3.
BASE_NEW_CVE: dict[str, Any] = {
    "schema_version": 1,
    "nodes": [
        _node("new_cve", "trigger.cve_published", "Nouvelle CVE NVD", 0, 0),
        _node(
            "cve_changed",
            "trigger.cve_updated",
            "CPE ou CVSS ajouté",
            0,
            160,
            change_types=["cpe_added", "cvss_added"],
        ),
        _node("scope", "vuln.scope_match", "Périmètre de veille", 260, 80),
        _node("upsert", "vuln.upsert", "Fiche vulnérabilité", 520, 40),
        _node("enrich", "vuln.enrich", "CVSS, EPSS, KEV", 780, 40),
        _node("technologies", "vuln.match_technologies", "Technologies", 1040, 40),
        _node(
            "urgent",
            "control.if",
            "KEV ou critique",
            1300,
            40,
            condition={"$expr": "json.kev || json.severity == 'CRITICAL'"},
        ),
        _node("notify", "notify.email", "Alerte aux analystes", 1560, 0),
    ],
    "edges": [
        _edge(1, "new_cve", "scope"),
        _edge(2, "cve_changed", "scope"),
        _edge(3, "scope", "upsert", port="in_scope"),
        _edge(4, "upsert", "enrich"),
        _edge(5, "enrich", "technologies"),
        _edge(6, "technologies", "urgent"),
        _edge(7, "urgent", "notify", port="true"),
    ],
}


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _cve(
    database: Database, cve_id: str, *, cpes: list[str], kev: bool = False, score: float = 9.8
) -> None:
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, cpe_criteria, base_score, severity, "
        "published_at, first_seen_at, synced_at, sources, kev, vuln_status) VALUES ($1, $2, $3, "
        "$4, 'CRITICAL', now(), now(), now(), ARRAY['nvd'], $5::jsonb, 'Analyzed')",
        cve_id,
        "A remote code execution in a widely used library.",
        cpes,
        score,
        json.dumps({"date_added": "2026-10-20"}) if kev else None,
    )


async def _event(database: Database, type_: str, payload: dict[str, Any]) -> None:
    await _sql(
        database,
        "INSERT INTO outbox_events (type, payload, attempts) VALUES ($1, $2::jsonb, 0)",
        type_,
        json.dumps(payload),
    )


async def _follow_log4j(database: Database, workspace_id: uuid.UUID) -> None:
    rows = await _sql(
        database,
        "INSERT INTO technologies (id, vendor, product, display_name, cpe_prefixes) VALUES "
        "($1, 'apache', 'log4j', 'Apache Log4j', ARRAY['cpe:2.3:a:apache:log4j']) "
        "ON CONFLICT (vendor, product) DO UPDATE SET vendor = excluded.vendor RETURNING id",
        uuid.uuid4(),
    )
    await _sql(
        database,
        "INSERT INTO watch_scopes (workspace_id, mode, technology_ids, updated_at) "
        "VALUES ($1, 'scoped', $2, now())",
        workspace_id,
        [rows[0]["id"]],
    )


async def _runs(h: Harness, workspace_id: uuid.UUID) -> list[WorkflowRun]:
    async with h.app_db(workspace_id) as db:
        rows = await db.execute(select(WorkflowRun).order_by(WorkflowRun.id))
        return list(rows.scalars())


async def _node_runs(h: Harness, workspace_id: uuid.UUID, run_id: uuid.UUID) -> dict[str, NodeRun]:
    async with h.app_db(workspace_id) as db:
        rows = await db.execute(
            select(NodeRun).where(NodeRun.run_id == run_id).order_by(NodeRun.attempt)
        )
        return {n.node_id: n for n in rows.scalars()}


def _linear(
    *nodes: tuple[str, str, dict[str, Any]], settings: dict[str, Any] | None = None
) -> dict[str, Any]:
    graph_nodes = [
        {"id": "start", "type": "trigger.manual", "params": {}},
        *({"id": nid, "type": t, "params": p, "settings": settings or {}} for nid, t, p in nodes),
    ]
    ids = [n["id"] for n in graph_nodes]
    edges = [
        {"id": f"e{i}", "from": {"node": a, "port": "out"}, "to": {"node": b, "port": "in"}}
        for i, (a, b) in enumerate(pairwise(ids))
    ]
    return {"schema_version": 1, "nodes": graph_nodes, "edges": edges}


async def _manual(
    h: Harness,
    workflow_id: uuid.UUID,
    workspace_id: uuid.UUID,
    payload: dict[str, Any],
    key: str | None = None,
) -> uuid.UUID:
    from app.workflows.engine import advance_task, start_run  # noqa: PLC0415
    from app.workflows.models import Workflow, WorkflowVersion  # noqa: PLC0415

    async with h.app_db(workspace_id) as db:
        workflow = await db.get(Workflow, workflow_id)
        assert workflow is not None
        assert workflow.active_version_id is not None
        version = await db.get(WorkflowVersion, workflow.active_version_id)
        assert version is not None
        run_id = await start_run(
            db,
            workflow,
            version,
            trigger_node_id="start",
            trigger_type="manual",
            payload=payload,
            idempotency_key=key or str(uuid.uuid4()),
            now=h.now,
        )
        await db.commit()
    assert run_id is not None
    advance_task(h.tasks, run_id, workspace_id)
    return run_id


async def test_new_nvd_cve_creates_vulnerability_in_matching_workspaces(
    database: Database, redis_url: str, clean_state: None
) -> None:
    """Exit criterion of phase 3 (PLAN.md)."""
    await create_user(database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"})
    await _follow_log4j(database, VOC)
    await _sql(
        database,
        "INSERT INTO watch_scopes (workspace_id, always_include_kev, updated_at) "
        "VALUES ($1, false, now())",
        CERT,
    )
    await _cve(database, "CVE-2026-1001", cpes=[LOG4J_CPE], kev=True)
    await _cve(database, "CVE-2026-1002", cpes=[])
    async with harness(database, redis_url) as h:
        for workspace_id in (VOC, CERT):
            await h.workflow(workspace_id, "Nouvelle CVE NVD", BASE_NEW_CVE)
        await _event(
            database, "cve.published", {"cve_id": "CVE-2026-1001", "change_types": ["published"]}
        )
        await _event(
            database, "cve.published", {"cve_id": "CVE-2026-1002", "change_types": ["published"]}
        )
        assert await h.dispatch() == 4  # 2 CVEs x 2 workspaces

        voc_runs, cert_runs = await _runs(h, VOC), await _runs(h, CERT)
        assert [r.status for r in voc_runs + cert_runs] == ["succeeded"] * 4
        first = await _node_runs(h, VOC, voc_runs[0].id)
        assert first["scope"].output["in_scope"][0]["json"]["scope"]["decision"] == "in_scope"
        assert first["upsert"].output["out"][0]["json"]["created"] is True
        assert first["enrich"].output["out"][0]["json"]["kev"] is True
        assert (
            first["technologies"].output["out"][0]["json"]["technologies"][0]["product"] == "log4j"
        )
        assert first["notify"].status == "succeeded"
        assert first["cve_changed"].status == "skipped"
        assert all(n.logs is not None for n in first.values())
        out_of_scope = await _node_runs(h, VOC, voc_runs[1].id)
        assert out_of_scope["upsert"].status == "skipped"
        assert [m["to"] for m in h.mails] == ["voc@voc.example.com"]

        rows = await _sql(
            database,
            "SELECT v.cve_id, v.exploitation_status, a.workspace_id, a.status "
            "FROM vulnerabilities v JOIN vulnerability_assessments a ON a.vulnerability_id = v.id",
        )
        assert [(r["cve_id"], r["workspace_id"], r["status"]) for r in rows] == [
            ("CVE-2026-1001", VOC, "new")
        ]
        assert rows[0]["exploitation_status"] == "exploited_itw"

        # NVD adds a matching CPE to the second CVE: it enters the VOC scope.
        await _sql(
            database,
            "UPDATE cve_records SET cpe_criteria = $1 WHERE cve_id = 'CVE-2026-1002'",
            [LOG4J_CPE],
        )
        await _event(
            database, "cve.updated", {"cve_id": "CVE-2026-1002", "change_types": ["cpe_added"]}
        )
        await _event(
            database, "cve.updated", {"cve_id": "CVE-2026-1002", "change_types": ["rejected"]}
        )
        assert await h.dispatch() == 2  # the "rejected" change matches no trigger
        rows = await _sql(database, "SELECT cve_id FROM vulnerabilities ORDER BY cve_id")
        assert [r["cve_id"] for r in rows] == ["CVE-2026-1001", "CVE-2026-1002"]

        # Replaying the outbox starts nothing twice.
        await _sql(database, "UPDATE outbox_events SET dispatched_at = NULL")
        assert await h.dispatch() == 0


async def test_retries_then_on_error(database: Database, redis_url: str, clean_state: None) -> None:
    FAILURES.clear()
    async with harness(database, redis_url) as h:
        retried = await h.workflow(
            VOC,
            "retried",
            _linear(
                ("flaky", "test.flaky", {"key": "a", "failures": 2}),
                settings={"retry": {"max_attempts": 3, "backoff_seconds": 0}},
            ),
        )
        run_id = await _manual(h, retried, VOC, {"x": 1})
        await h.drain()
        nodes = await _node_runs(h, VOC, run_id)
        assert nodes["flaky"].attempt == 3
        assert nodes["flaky"].output["out"][0]["json"] == {"x": 1}
        assert (await _runs(h, VOC))[0].status == "succeeded"

        stopped = await h.workflow(
            VOC,
            "stopped",
            _linear(
                ("flaky", "test.flaky", {"key": "b", "failures": 5}),
                ("after", "transform.limit", {"count": 1}),
            ),
        )
        run_id = await _manual(h, stopped, VOC, {})
        await h.drain()
        runs = {r.id: r for r in await _runs(h, VOC)}
        assert runs[run_id].status == "failed"
        assert runs[run_id].error == "flaky: flaky"
        assert "after" not in await _node_runs(h, VOC, run_id)

        continued = await h.workflow(
            VOC,
            "continued",
            _linear(
                ("flaky", "test.flaky", {"key": "c", "failures": 5}),
                ("after", "transform.limit", {"count": 1}),
                settings={"on_error": "continue"},
            ),
        )
        run_id = await _manual(h, continued, VOC, {})
        await h.drain()
        nodes = await _node_runs(h, VOC, run_id)
        assert nodes["flaky"].status == "failed"
        assert nodes["after"].status == "skipped"
        assert {r.id: r for r in await _runs(h, VOC)}[run_id].status == "succeeded"


async def test_idempotent_tasks_cancellation_and_recovery(
    database: Database, redis_url: str, clean_state: None
) -> None:
    FAILURES.clear()
    async with harness(database, redis_url) as h:
        workflow_id = await h.workflow(VOC, "wf", _linear(("a", "test.flaky", {"key": "d"})))
        run_id = await _manual(h, workflow_id, VOC, {"n": 1}, key="same")
        with pytest.raises(AssertionError):
            await _manual(h, workflow_id, VOC, {"n": 1}, key="same")  # no second run
        await h.drain(skip_nodes=True)
        h.parked.clear()  # the message is lost
        node = (await _node_runs(h, VOC, run_id))["a"]
        assert node.status == "queued"

        # Lost message: the sweep re-sends it; a replayed task does nothing more.
        await _sql(database, "UPDATE node_runs SET scheduled_at = now() - interval '1 hour'")
        assert (await h.sweep())["resent"] == 1
        replay = list(h.tasks.sent)
        await h.drain()
        h.tasks.sent.extend(replay)
        await h.drain()
        assert FAILURES["d"] == 1
        nodes = await _node_runs(h, VOC, run_id)
        assert nodes["a"].status == "succeeded"
        assert nodes["a"].attempt == 1

        # Worker lost while running: the sweep fails it, the retry policy applies.
        run_id = await _manual(h, workflow_id, VOC, {"n": 2})
        await h.drain(skip_nodes=True)
        await _sql(
            database,
            "UPDATE node_runs SET status = 'running', started_at = now() - interval '2 hours' "
            "WHERE run_id = $1",
            run_id,
        )
        assert (await h.sweep())["recovered"] == 1
        await h.drain()
        assert (await _node_runs(h, VOC, run_id))["a"].error == "worker_lost"
        assert {r.id: r for r in await _runs(h, VOC)}[run_id].status == "failed"

        # Cancellation: queued work is cancelled, the run ends cancelled.
        run_id = await _manual(h, workflow_id, VOC, {"n": 3})
        await h.drain(skip_nodes=True)
        await _sql(
            database, "UPDATE workflow_runs SET cancel_requested = true WHERE id = $1", run_id
        )
        from app.workflows.engine import advance_task  # noqa: PLC0415

        advance_task(h.tasks, run_id, VOC)
        await h.drain()
        assert {r.id: r for r in await _runs(h, VOC)}[run_id].status == "cancelled"
        assert (await _node_runs(h, VOC, run_id))["a"].status == "cancelled"


async def test_concurrency_limit_and_approval(
    database: Database, redis_url: str, clean_state: None
) -> None:
    await create_user(database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"})
    async with harness(database, redis_url, Limits(concurrent_per_workflow=1)) as h:
        graph = {
            "schema_version": 1,
            "nodes": [
                {"id": "start", "type": "trigger.manual"},
                {"id": "approve", "type": "control.approval"},
                {"id": "sink", "type": "test.sink"},
            ],
            "edges": [
                {
                    "id": "e1",
                    "from": {"node": "start", "port": "out"},
                    "to": {"node": "approve", "port": "in"},
                },
                {
                    "id": "e2",
                    "from": {"node": "approve", "port": "approved"},
                    "to": {"node": "sink", "port": "in"},
                },
            ],
        }
        workflow_id = await h.workflow(VOC, "approval", graph)
        first = await _manual(h, workflow_id, VOC, {"n": 1})
        await h.drain()
        assert [m["to"] for m in h.mails] == ["voc@voc.example.com"]
        runs = {r.id: r for r in await _runs(h, VOC)}
        assert runs[first].status == "waiting_approval"

        # Waiting runs hold no slot; a second running run would exceed the limit of one.
        flaky = await h.workflow(VOC, "slow", _linear(("a", "test.flaky", {"key": "e"})))
        r1 = await _manual(h, flaky, VOC, {})
        r2 = await _manual(h, flaky, VOC, {})
        await h.drain(skip_nodes=True)
        runs = {r.id: r for r in await _runs(h, VOC)}
        assert sorted([runs[r1].status, runs[r2].status]) == ["queued", "running"]
        h.unpark()
        await h.drain()
        runs = {r.id: r for r in await _runs(h, VOC)}
        assert runs[r1].status == runs[r2].status == "succeeded"

        async with h.app_db(VOC) as db:
            run = await db.get(WorkflowRun, first)
            assert run is not None
            user = (await _sql(database, "SELECT id FROM users"))[0]["id"]
            assert await decide_approval(
                db, run, "approve", approved=True, actor=user, comment="ok", now=h.now
            )
            assert not await decide_approval(
                db, run, "approve", approved=True, actor=user, comment="again", now=h.now
            )
            await db.commit()
        from app.workflows.engine import advance_task  # noqa: PLC0415

        advance_task(h.tasks, first, VOC)
        await h.drain()
        nodes = await _node_runs(h, VOC, first)
        assert nodes["sink"].output["out"][0]["json"] == {"n": 1}
        assert {r.id: r for r in await _runs(h, VOC)}[first].status == "succeeded"


async def test_run_deadline(database: Database, redis_url: str, clean_state: None) -> None:
    async with harness(database, redis_url) as h:
        workflow_id = await h.workflow(VOC, "wf", _linear(("a", "test.flaky", {"key": "f"})))
        run_id = await _manual(h, workflow_id, VOC, {})
        await h.drain(skip_nodes=True)
        await _sql(
            database,
            "UPDATE workflow_runs SET deadline_at = now() - $1::interval WHERE id = $2",
            timedelta(minutes=1),
            run_id,
        )
        await h.sweep()
        await h.drain()
        run = {r.id: r for r in await _runs(h, VOC)}[run_id]
        assert run.status == "timed_out"


FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>CERT-FR</title>
<item><title>Multiples vuln\xc3\xa9rabilit\xc3\xa9s dans Apache Log4j</title>
<link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/</link>
<description>&lt;p&gt;CVE-2026-1001 et CVE-2026-1003&lt;/p&gt;</description>
<pubDate>Tue, 20 Oct 2026 10:00:00 +0200</pubDate></item>
<item><title>Bulletin sans CVE</title><link>https://www.cert.ssi.gouv.fr/avis/2/</link>
<description>Rien</description></item></channel></rss>"""


async def test_rss_source_through_a_connector(
    database: Database, redis_url: str, clean_state: None
) -> None:
    connector_id = uuid.uuid4()
    await _sql(
        database,
        "INSERT INTO connectors (id, workspace_id, family, kind, name, config, egress_domains) "
        "VALUES ($1, $2, 'source', 'rss', 'CERT-FR', $3, ARRAY['www.cert.ssi.gouv.fr'])",
        connector_id,
        VOC,
        json.dumps({"allowed_domains": ["www.cert.ssi.gouv.fr"]}),
    )
    web = FakeWeb()
    web.raw("https://www.cert.ssi.gouv.fr/avis/feed/", FEED, "application/rss+xml")
    async with harness(database, redis_url) as h:
        h.deps.http = web.client("www.cert.ssi.gouv.fr")
        graph = _linear(
            (
                "feed",
                "source.rss",
                {
                    "connector_id": str(connector_id),
                    "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
                },
            ),
            ("cves", "transform.extract_cve", {}),
            ("upsert", "vuln.upsert", {"evidence_kind": "advisory"}),
        )
        workflow_id = await h.workflow(VOC, "CERT-FR", graph)
        run_id = await _manual(h, workflow_id, VOC, {})
        await h.drain()
        nodes = await _node_runs(h, VOC, run_id)
        assert nodes["feed"].status == "succeeded", nodes["feed"].error
        assert nodes["feed"].output["out"][0]["meta"]["trust"] == "untrusted"
        assert nodes["cves"].output_count == 1
        assert nodes["upsert"].output_count == 2

        rows = await _sql(
            database,
            "SELECT v.cve_id, e.kind, c.title FROM vulnerability_evidence e "
            "JOIN vulnerabilities v ON v.id = e.vulnerability_id "
            "JOIN collected_items c ON c.id = e.collected_item_id ORDER BY v.cve_id",
        )
        assert [(r["cve_id"], r["kind"]) for r in rows] == [
            ("CVE-2026-1001", "advisory"),
            ("CVE-2026-1003", "advisory"),
        ]

        # Second run: entries already collected are not emitted again (only_new).
        run_id = await _manual(h, workflow_id, VOC, {})
        await h.drain()
        nodes = await _node_runs(h, VOC, run_id)
        assert nodes["feed"].output_count == 0
        assert nodes["cves"].status == "skipped"

        # A connector of another workspace cannot be used, even by a stored graph.
        await _sql(database, "UPDATE connectors SET workspace_id = $1", CERT)
        run_id = await _manual(h, workflow_id, VOC, {})
        await h.drain()
        assert (await _node_runs(h, VOC, run_id))["feed"].error == "connector_not_found"
