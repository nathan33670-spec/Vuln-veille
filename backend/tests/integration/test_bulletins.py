"""Bulletins end to end (plan 6.4 to 6.8), on a simulated AI engine: a draft requested on
a CVE with the template chosen by the rules, edits and revisions, marking, simple then
double validation, publication with a recent second factor, the other team's read-only
view, a regenerated field, a linked translation, withdrawal, and the workflow node."""

import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import pyotp
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.runtime import AgentDeps
from app.ai.models import AIModel
from app.bulletins.runner import run_draft_request
from app.core.db import create_engine, create_sessionmaker
from app.core.tasks import MemoryTaskQueue
from app.vault.service import Vault
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.bulletin_support import Writer, setup_bulletins, sql
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, SeededUser, create_user
from tests.integration.workflow_harness import harness

pytestmark = pytest.mark.integration

VOC = WORKSPACE_IDS["voc"]
CVE = "CVE-2026-6001"


class Session:
    def __init__(self, api: Api, user: SeededUser, csrf: str) -> None:
        self.api, self.user, self.h = api, user, {"x-csrf-token": csrf}

    async def get(self, path: str, status: int = 200) -> Any:
        response = await self.api.client.get(self.api.url(path))
        assert response.status_code == status, response.text
        return response.json()

    async def post(self, path: str, body: Any = None, status: int = 200) -> Any:
        response = await self.api.client.post(self.api.url(path), json=body, headers=self.h)
        assert response.status_code == status, response.text
        return response.json()

    async def patch(self, path: str, body: Any, status: int = 200) -> Any:
        response = await self.api.client.patch(self.api.url(path), json=body, headers=self.h)
        assert response.status_code == status, response.text
        return response.json()

    async def step_up(self) -> None:
        # The sign-in code cannot be replayed; the next window is accepted.
        assert self.user.totp_secret is not None
        code = pyotp.TOTP(self.user.totp_secret).at(int(time.time()) + 30)
        confirmed = await self.post("/auth/step-up", {"code": code})
        self.h = {"x-csrf-token": confirmed["csrf_token"]}


async def _login(make_api: ApiFactory, user: SeededUser) -> Session:
    api = await make_api("backoffice")
    return Session(api, user, await sign_in(api, user))


async def test_bulletin_lifecycle(make_api: ApiFactory, database: Database, redis_url: str) -> None:
    await setup_bulletins(database, redis_url, CVE)
    ana = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    bob = await create_user(
        database.admin_dsn, "bob@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    a = await _login(make_api, ana)
    base = "/workspaces/voc"

    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)),
        redis_url=SecretStr(redis_url),
    )
    engine = create_engine(settings.database_url_worker.get_secret_value())
    sessions = create_sessionmaker(engine)
    writer = Writer()

    async def engine_for(db: AsyncSession, model: AIModel) -> Writer:
        return writer

    deps = AgentDeps(
        settings,
        Vault(public_keys={}, keyrings=TEST_KEYRINGS),
        clock=lambda: datetime.now(UTC),
        tasks=MemoryTaskQueue(),
        engine_for=engine_for,
    )

    async def work(session: Session, request_id: str) -> dict[str, Any]:
        name, kwargs = session.api.tasks.sent.pop()
        assert (name, kwargs["request_id"]) == ("ai.bulletin_draft", request_id)
        await run_draft_request(sessions, deps, uuid.UUID(request_id), VOC)
        return dict(await session.get(f"{base}/draft-requests/{request_id}"))

    try:
        # A draft on a CVE not followed yet: the vulnerability is created, the KEV rule
        # picks the urgent template, the worker generates the fields.
        requested = await a.post(f"{base}/draft-requests", {"cve_id": CVE}, 202)
        assert (requested["template_name"], requested["selection_reasons"]) == (
            "Vulnérabilité exploitée ou critique (FR)",
            ["kev: true"],
        )
        done = await work(a, requested["id"])
        assert done["status"] == "succeeded", done
        assert [p["step"] for p in done["progress"]] == ["context", "done"]
        bid = done["bulletin_id"]
        b = await a.get(f"{base}/bulletins/{bid}")
        assert (b["ref"], b["status"], b["tlp"], b["language"]) == (
            f"VOC-{datetime.now(UTC).year}-0001",
            "draft",
            "AMBER",
            "fr",
        )
        current = b["current"]
        assert (current["rev_no"], current["created_by_type"]) == (1, "ai")
        assert current["agent_run_id"]
        assert current["fields"]["cves"] == [CVE]  # computed, not generated
        assert [r["url"] for r in current["fields"]["references"]] == [
            "https://logging.apache.org/security.html"
        ]  # the javascript: reference is dropped
        assert "<script" not in current["rendered_html"]
        assert "&lt;script&gt;" in current["rendered_html"]  # shown as text
        assert [v["cve_id"] for v in b["vulnerabilities"]] == [CVE]

        # Edits are revisions, checked against the template; concurrent edits detected.
        fields = {**current["fields"], "analyst_note": "Vu avec l'équipe réseau."}
        bad = await a.post(
            f"{base}/bulletins/{bid}/revisions",
            {"fields": {**fields, "severity": "bogus"}, "base_rev_no": 1},
            422,
        )
        assert bad["errors"] == [{"path": "fields.severity", "code": "enum"}]
        b = await a.post(
            f"{base}/bulletins/{bid}/revisions",
            {"fields": fields, "change_note": "Note ajoutée", "base_rev_no": 1},
            201,
        )
        assert b["current"]["rev_no"] == 2
        await a.post(f"{base}/bulletins/{bid}/revisions", {"fields": fields, "base_rev_no": 1}, 409)
        b = await a.patch(f"{base}/bulletins/{bid}", {"tlp": "GREEN", "version": b["version"]})
        assert (b["tlp"], b["current"]["rev_no"]) == ("GREEN", 3)
        assert "TLP:GREEN" in b["current"]["rendered_html"]
        # The editor's preview renders with the bulletin's marking; audiences by name.
        preview = await a.post(
            f"{base}/bulletin-templates/preview",
            {"spec": b["template_spec"], "fields": b["current"]["fields"], "tlp": "RED"},
        )
        assert "TLP:RED" in preview["html"]
        assert "&lt;script&gt;" in preview["html"]
        assert await a.get(f"{base}/bulletin-audiences") == []

        # Simple validation (Q4): the author approves; publication needs a fresh factor.
        b = await a.post(f"{base}/bulletins/{bid}/approve", {"version": b["version"]})
        assert b["status"] == "approved"
        await sql(database, "UPDATE sessions SET step_up_at = now() - interval '1 hour'")
        refused = await a.api.client.post(
            a.api.url(f"{base}/bulletins/{bid}/publish"),
            json={"version": b["version"]},
            headers=a.h,
        )
        assert refused.json()["detail"] == "step_up_required"
        await a.step_up()
        b = await a.post(f"{base}/bulletins/{bid}/publish", {"version": b["version"]})
        assert (b["status"], b["published_rev_no"]) == ("published", 3)

        # The other team reads what was published, and nothing else.
        e = await _login(make_api, eve)
        shared = await e.get("/workspaces/cert/bulletins?scope=shared")
        assert [s["ref"] for s in shared] == [b["ref"]]
        seen = await e.get(f"/workspaces/cert/bulletins/{bid}")
        assert (seen["own"], seen["current"]["rev_no"], seen["revisions"]) == (False, 3, [])
        await e.post(
            f"/workspaces/cert/bulletins/{bid}/revisions",
            {"fields": fields, "base_rev_no": 3},
            404,
        )

        # An update goes back through review; the published revision stays visible.
        b = await a.post(
            f"{base}/bulletins/{bid}/revisions",
            {"fields": {**fields, "analyst_note": "Mise à jour."}, "base_rev_no": 3},
            201,
        )
        assert (b["status"], b["current"]["rev_no"], b["published_rev_no"]) == ("draft", 4, 3)
        assert (await e.get(f"/workspaces/cert/bulletins/{bid}"))["current"]["rev_no"] == 3

        # Double validation, once the workspace enables it.
        current_settings = await a.get(f"{base}/bulletin-settings")
        await a.api.client.put(
            a.api.url(f"{base}/bulletin-settings"),
            json={
                "ref_prefix": "VOC",
                "review_required": True,
                "default_template_id": current_settings["default_template_id"],
                "version": current_settings["version"],
            },
            headers=a.h,
        )
        b = await a.post(f"{base}/bulletins/{bid}/submit", {"version": b["version"]})
        assert b["status"] == "in_review"
        self_review = await a.api.client.post(
            a.api.url(f"{base}/bulletins/{bid}/approve"),
            json={"version": b["version"]},
            headers=a.h,
        )
        assert self_review.json()["detail"] == "reviewer_must_differ"
        r = await _login(make_api, bob)
        b = await r.post(f"{base}/bulletins/{bid}/approve", {"version": b["version"]})
        assert (b["status"], b["reviewer_id"]) == ("approved", str(bob.id))
        await r.step_up()
        b = await r.post(f"{base}/bulletins/{bid}/publish", {"version": b["version"]})
        assert b["published_rev_no"] == 4

        # One field regenerated with an instruction: a new AI revision, reviewed again.
        regen = await a.post(
            f"{base}/bulletins/{bid}/regenerate",
            {"field": "summary", "instructions": "Plus court."},
            202,
        )
        assert (await work(a, regen["id"]))["status"] == "succeeded"
        b = await a.get(f"{base}/bulletins/{bid}")
        assert b["current"]["fields"]["summary"] == "Résumé réécrit, plus court."
        assert (b["current"]["created_by_type"], b["status"]) == ("ai", "draft")
        assert b["current"]["fields"]["analyst_note"] == "Mise à jour."  # the rest kept

        # Translation from the validated text, linked to its source.
        await a.post(f"{base}/bulletins/{bid}/translations", {"language": "en"}, 409)
        b = await a.post(f"{base}/bulletins/{bid}/submit", {"version": b["version"]})
        b = await r.post(f"{base}/bulletins/{bid}/approve", {"version": b["version"]})
        translation = await a.post(f"{base}/bulletins/{bid}/translations", {"language": "en"}, 202)
        assert translation["template_name"] == "Generic bulletin (EN)"
        en = await work(a, translation["id"])
        assert en["status"] == "succeeded"
        english = await a.get(f"{base}/bulletins/{en['bulletin_id']}")
        assert (english["language"], english["translation_of"]["id"]) == ("en", bid)
        assert english["current"]["fields"]["title"] == "Log4j RCE"
        assert english["tlp"] == "GREEN"  # the source's marking
        assert english["ref"].endswith("-0002")
        assert any("traduire fidèlement" in s for s in writer.systems)

        # Withdrawal (the step-up above is still recent): off the other team's view.
        b = await a.get(f"{base}/bulletins/{bid}")
        b = await a.post(
            f"{base}/bulletins/{bid}/withdraw", {"reason": "Doublon", "version": b["version"]}
        )
        assert (b["status"], b["withdrawn_reason"]) == ("withdrawn", "Doublon")
        await e.get(f"/workspaces/cert/bulletins/{bid}", 404)
        audit = await sql(
            database, "SELECT action FROM audit_events WHERE action LIKE 'bulletin.%'"
        )
        assert {
            "bulletin.draft_requested",
            "bulletin.edited",
            "bulletin.updated",
            "bulletin.approved",
            "bulletin.published",
            "bulletin.submitted",
            "bulletin.translation_requested",
            "bulletin.withdrawn",
        } <= {row["action"] for row in audit}
    finally:
        await engine.dispose()


def _edge(edge_id: str, source: str, target: str) -> dict[str, Any]:
    return {
        "id": edge_id,
        "from": {"node": source, "port": "out"},
        "to": {"node": target, "port": "in"},
    }


async def test_generate_draft_node(database: Database, redis_url: str, clean_state: None) -> None:
    await setup_bulletins(database, redis_url, CVE)
    writer = Writer()

    async def engine_for(db: AsyncSession, model: AIModel) -> Writer:
        return writer

    graph = {
        "schema_version": 1,
        "nodes": [
            {"id": "start", "type": "trigger.manual", "params": {}},
            {"id": "upsert", "type": "vuln.upsert", "params": {}},
            {"id": "draft", "type": "bulletin.generate_draft", "params": {"language": "fr"}},
        ],
        "edges": [_edge("e1", "start", "upsert"), _edge("e2", "upsert", "draft")],
    }
    async with harness(database, redis_url) as h:
        h.deps.agent_engine = engine_for
        workflow_id = await h.workflow(VOC, "Draft automatique", graph)
        run_id = await h.manual(VOC, workflow_id, {"cve_id": CVE})
        await h.drain()
    rows = await sql(
        database,
        "SELECT b.ref, b.status, r.created_by_type FROM bulletins b "
        "JOIN bulletin_revisions r ON r.id = b.current_revision_id",
    )
    assert [(r["status"], r["created_by_type"]) for r in rows] == [("draft", "ai")]
    output = await sql(
        database,
        "SELECT output FROM node_runs WHERE run_id = $1 AND node_id = 'draft'",
        run_id,
    )
    item = json.loads(output[0]["output"])["out"][0]["json"]["bulletin"]
    assert (item["status"], item["ref"]) == ("draft", rows[0]["ref"])
