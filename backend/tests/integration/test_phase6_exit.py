"""Exit criterion of phase 6 (PLAN.md), in a real browser against the real API.

With double validation enabled in the VOC workspace, an analyst requests a draft on a
CVE: the template chosen by the rules (KEV) is applied, the AI engine writes the
fields, the analyst edits the draft and submits it; a second analyst validates and
publishes it, with a recent second factor. The engine is simulated; everything else is
the production path, served with the production CSP (browser.py).
"""

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.runtime import AgentDeps
from app.ai.models import AIModel
from app.bulletins.runner import DRAFT_TASK, run_draft_request
from app.core.db import create_engine, create_sessionmaker
from app.core.tasks import MemoryTaskQueue
from app.vault.service import Vault
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.browser import NEEDS_BROWSER, free_port, run_script, served
from tests.integration.bulletin_support import Writer, setup_bulletins, sql
from tests.integration.conftest import PASSWORDS, Database
from tests.integration.seed import create_user

SCRIPT = Path(__file__).with_name("phase6_exit.cjs")
CVE = "CVE-2026-6101"

pytestmark = [pytest.mark.integration, NEEDS_BROWSER]


async def _pump(api: FastAPI, deps: AgentDeps, database: Database) -> None:
    """The ``ai`` worker: draft requests queued by the API run in-process."""
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    sessions = create_sessionmaker(engine)
    queue: MemoryTaskQueue = api.state.tasks
    try:
        while True:
            while queue.sent:
                name, kwargs = queue.sent.pop(0)
                if name == DRAFT_TASK:
                    await run_draft_request(
                        sessions,
                        deps,
                        uuid.UUID(kwargs["request_id"]),
                        uuid.UUID(kwargs["workspace_id"]),
                    )
            await asyncio.sleep(0.2)
    finally:
        await engine.dispose()


async def test_phase_6_exit_in_a_browser(
    database: Database, redis_url: str, clean_state: None, tmp_path: Path
) -> None:
    await setup_bulletins(database, redis_url, CVE)
    await sql(database, "UPDATE bulletin_settings SET review_required = true")
    ana = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    bob = await create_user(
        database.admin_dsn, "bob@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    writer = Writer()

    async def engine_for(db: AsyncSession, model: AIModel) -> Writer:
        return writer

    deps = AgentDeps(
        make_settings(redis_url=SecretStr(redis_url)),
        Vault(public_keys={}, keyrings=TEST_KEYRINGS),
        clock=lambda: datetime.now(UTC),
        tasks=MemoryTaskQueue(),
        engine_for=engine_for,
    )
    port = free_port()
    async with served(database, redis_url, port) as api:
        pump = asyncio.create_task(_pump(api, deps, database))
        code, report = await run_script(
            str(SCRIPT),
            {
                "base": f"http://localhost:{port}",
                "author": {
                    "email": ana.email,
                    "password": ana.password,
                    "totpSecret": ana.totp_secret,
                },
                "reviewer": {
                    "email": bob.email,
                    "password": bob.password,
                    "totpSecret": bob.totp_secret,
                },
                "cve": CVE,
                "artifacts": str(tmp_path),
            },
        )
        pump.cancel()
    assert code == 0, report

    rows = await sql(
        database,
        "SELECT b.status, b.author_id, b.submitted_by, b.reviewer_id, b.published_by, "
        "r.rev_no, r.fields, r.created_by_type, r.rendered_html "
        "FROM bulletins b JOIN bulletin_revisions r ON r.id = b.published_revision_id",
    )
    assert len(rows) == 1, report
    published = rows[0]
    assert published["status"] == "published"
    assert (published["author_id"], published["submitted_by"]) == (ana.id, ana.id)
    assert (published["reviewer_id"], published["published_by"]) == (bob.id, bob.id)
    # The analyst's edit is what was validated and published (revision 2, by a person).
    assert (published["rev_no"], published["created_by_type"]) == (2, "user")
    assert "Vu avec l'équipe réseau" in published["rendered_html"]
    assert "<script>" not in published["rendered_html"]
    template = await sql(
        database,
        "SELECT t.name FROM bulletins b JOIN bulletin_template_versions v "
        "ON v.id = b.template_version_id JOIN bulletin_templates t ON t.id = v.template_id",
    )
    assert template[0]["name"] == "Vulnérabilité exploitée ou critique (FR)"
    audit = {
        r["action"]
        for r in await sql(
            database, "SELECT action FROM audit_events WHERE action LIKE 'bulletin.%'"
        )
    }
    assert {
        "bulletin.draft_requested",
        "bulletin.edited",
        "bulletin.submitted",
        "bulletin.approved",
        "bulletin.published",
    } <= audit
