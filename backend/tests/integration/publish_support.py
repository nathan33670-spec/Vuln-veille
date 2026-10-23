"""Shared by the publication tests: templates, a validated bulletin, a signed-in client."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import httpx

from app.bulletins.seeds import seed_templates
from tests.integration.conftest import Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, SeededUser
from tests.integration.workflow_harness import harness
from tests.web_fakes import FakeWeb

BASE = "https://api.partner.example"


async def sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def seed_all_templates(database: Database, redis_url: str) -> None:
    async with harness(database, redis_url) as h:
        for slug in ("voc", "cert"):
            async with h.app_db(WORKSPACE_IDS[slug]) as db:
                await seed_templates(db, WORKSPACE_IDS[slug], slug, datetime.now(UTC))
                await db.commit()


async def validated_bulletin(database: Database, workspace: uuid.UUID, status: str) -> uuid.UUID:
    """A bulletin of the delivered generic template, with one revision."""
    version = (
        await sql(
            database,
            "SELECT v.id FROM bulletin_template_versions v JOIN bulletin_templates t "
            "ON t.id = v.template_id WHERE t.workspace_id = $1 AND t.seed_key = 'generic_fr'",
            workspace,
        )
    )[0]["id"]
    bulletin, revision = uuid.uuid4(), uuid.uuid4()
    fields = {
        "title": "RCE dans Exemple",
        "summary": "Une faille.",
        "recommendations": "Mettre à jour.",
        "affected_products": [{"vendor": "exemple", "product": "serveur", "versions": "< 2"}],
        "references": [{"title": "Avis", "url": "https://exemple.org/avis"}],
    }
    await sql(
        database,
        "INSERT INTO bulletins (id, workspace_id, ref, language, title, status, tlp, "
        "template_version_id, approved_at) VALUES ($1, $2, $3, 'fr', 'RCE', $4, 'GREEN', $5, "
        "now())",
        bulletin, workspace, f"CERT-2026-{uuid.uuid4().int % 10000:04d}", status, version,
    )  # fmt: skip
    await sql(
        database,
        "INSERT INTO bulletin_revisions (id, workspace_id, bulletin_id, rev_no, fields, "
        "rendered_markdown, rendered_html, content_hash, created_by_type) "
        "VALUES ($1, $2, $3, 1, $4, '# RCE dans Exemple', '<h1>RCE</h1>', $5, 'user')",
        revision, workspace, bulletin, json.dumps(fields), "b" * 64,
    )  # fmt: skip
    await sql(
        database, "UPDATE bulletins SET current_revision_id = $1 WHERE id = $2", revision, bulletin
    )
    return bulletin


class Client:
    def __init__(self, api: Api, csrf: str) -> None:
        self.api, self.h = api, {"x-csrf-token": csrf}

    async def call(self, method: str, path: str, body: Any = None, status: int = 200) -> Any:
        response = await self.api.client.request(
            method, self.api.url(path), json=body, headers=self.h
        )
        assert response.status_code == status, response.text
        return response.json() if response.content else None


async def login(make_api: ApiFactory, user: SeededUser) -> Client:
    api = await make_api("backoffice")
    return Client(api, await sign_in(api, user))


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
