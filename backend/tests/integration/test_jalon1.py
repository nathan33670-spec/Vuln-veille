"""Exit criterion of Jalon 1 (end of phase 4, PLAN.md), with no simulated engine object:
the real Gemini adapter (official SDK) and the real OpenAI-compatible adapter answer
through SafeHttpClient from simulated provider servers.

A new NVD CVE in the watch scope goes, without any intervention, through the delivered
investigation workflow and yields an unqualified vulnerability with a structured,
sourced synthesis. Then the workspace's preferred engine is switched to an
OpenAI-compatible endpoint through the API, and the next CVE goes through the same
workflow with no code change. (Trapped content is the injection corpus's part,
``test_injection_corpus.py``.)
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import httpx
import pytest

from app.ai.agents.presets import seed_agents
from app.vault.service import Vault
from app.workflows.seeds import NEW_CVE
from tests.conftest import TEST_KEYRINGS
from tests.integration.conftest import ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import harness
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]
CPE = "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
GEMINI = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
LLM = "https://llm.cert.example.org/v1/chat/completions"
POC = "https://github.com/acme/poc"


def _answer(system: str, first: str, has_results: bool) -> tuple[str, Any]:
    """What a well-behaved model answers, by agent: ("call", tool, args) or ("final", obj)."""
    if system.startswith("Tu es analyste"):
        return "final", {
            "relevant": True,
            "category": "RCE",
            "probable_technologies": ["Apache Log4j"],
            "duplicate_of": None,
            "suggested_priority": "P1",
            "rationale": "Log4j est suivi.",
            "confidence": "high",
        }
    if system.startswith("Tu cherches des preuves"):
        if not has_results:
            cve = next(w for w in first.replace('"', " ").split() if w.startswith("CVE-"))
            return "call", ("github_search", {"query": cve})
        return "final", {
            "poc": [
                {
                    "url": POC,
                    "description": "PoC public",
                    "reliability": "medium",
                    "suspicious": False,
                    "suspicion_reasons": [],
                }
            ],
            "summary": "Un PoC public.",
        }
    assert system.startswith("Tu rédiges la synthèse")
    return "final", {
        "summary": f"RCE dans Log4j ; un PoC public ({POC}).",
        "affected_products": [
            {"vendor": "apache", "product": "log4j", "versions": "< 2.17", "evidence": [POC]}
        ],
        "exploitation_status": "poc_public",
        "poc": [
            {
                "url": POC,
                "description": "PoC public",
                "reliability": "medium",
                "suspicious": False,
                "suspicion_reasons": [],
            }
        ],
        "patch_status": "available",
        "mitigations": [],
        "notable_discussions": [],
        "suggested_priority": "P1",
        "confidence": "medium",
        "open_questions": [],
    }


def gemini_server(request: httpx.Request) -> tuple[int, dict[str, Any]]:
    body = json.loads(request.content)
    system = body["systemInstruction"]["parts"][0]["text"]
    first = body["contents"][0]["parts"][0]["text"]
    has_results = any("functionResponse" in p for p in body["contents"][-1]["parts"])
    kind, value = _answer(system, first, has_results)
    if kind == "call":
        name, args = value
        parts: list[dict[str, Any]] = [{"functionCall": {"id": "c1", "name": name, "args": args}}]
    else:
        parts = [{"text": json.dumps(value)}]
    return 200, {
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 300, "candidatesTokenCount": 50},
        "modelVersion": "gemini-2.5-flash",
    }


def openai_server(request: httpx.Request) -> tuple[int, dict[str, Any]]:
    body = json.loads(request.content)
    messages = body["messages"]
    kind, value = _answer(
        messages[0]["content"], messages[1]["content"], messages[-1]["role"] == "tool"
    )
    if kind == "call":
        name, args = value
        message: dict[str, Any] = {
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)},
                }
            ],
        }
        finish = "tool_calls"
    else:
        message, finish = {"content": json.dumps(value)}, "stop"
    return 200, {
        "id": "c",
        "model": "llm-interne",
        "choices": [
            {"index": 0, "message": {"role": "assistant", **message}, "finish_reason": finish}
        ],
        "usage": {"prompt_tokens": 300, "completion_tokens": 50},
    }


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _publish(database: Database, cve_id: str) -> None:
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, cpe_criteria, base_score, severity, "
        "published_at, first_seen_at, synced_at, sources) VALUES ($1, 'RCE in Log4j', $2, 9.8, "
        "'CRITICAL', now(), now(), now(), ARRAY['nvd'])",
        cve_id,
        [CPE],
    )
    await _sql(
        database,
        "INSERT INTO outbox_events (type, payload, attempts) "
        "VALUES ('cve.published', $1::jsonb, 0)",
        json.dumps({"cve_id": cve_id, "change_types": ["published"]}),
    )


async def test_jalon_1(make_api: ApiFactory, database: Database, redis_url: str) -> None:
    user = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, user)}

    async def post(path: str, body: Any) -> Any:
        response = await api.client.post(api.url(path), json=body, headers=h)
        assert response.status_code in (200, 201), response.text
        return response.json()

    # The CERT follows Log4j, reads GitHub, and starts on the free Gemini tier.
    tech = await _sql(
        database,
        "INSERT INTO technologies (id, vendor, product, display_name, cpe_prefixes) VALUES "
        "($1, 'apache', 'log4j', 'Apache Log4j', ARRAY['cpe:2.3:a:apache:log4j']) RETURNING id",
        uuid.uuid4(),
    )
    await _sql(
        database,
        "INSERT INTO watch_scopes (workspace_id, mode, technology_ids, updated_at) "
        "VALUES ($1, 'scoped', $2, now())",
        CERT,
        [tech[0]["id"]],
    )
    await post("/workspaces/cert/connectors/source", {"kind": "github", "name": "GitHub"})
    key = await post(
        "/workspaces/cert/secrets", {"name": "gemini", "purpose": "llm", "value": "key-not-real"}
    )
    await post(
        "/workspaces/cert/connectors/ai_engine",
        {"kind": "gemini", "name": "Gemini gratuit", "secret_refs": {"api_key": key["id"]}},
    )
    await post(
        "/workspaces/cert/connectors/ai_engine",
        {
            "kind": "openai_compatible",
            "name": "LLMaaS",
            "config": {
                "base_url": "https://llm.cert.example.org/v1",
                "models": [{"model_id": "llm-interne"}],
            },
        },
    )
    models = {m["model_id"]: m["id"] for m in (await api.client.get(api.url("/ai-models"))).json()}

    async def prefer(model_id: str) -> None:
        response = await api.client.put(
            api.url("/workspaces/cert/ai-engine"),
            json={"model_row_id": models[model_id]},
            headers=h,
        )
        assert response.status_code == 200, response.text

    web = FakeWeb()
    web.routes[GEMINI] = gemini_server
    web.routes[LLM] = openai_server
    web.json(
        "https://api.github.com/search/repositories",
        {"items": [{"full_name": "acme/poc", "html_url": POC, "description": "PoC Log4j"}]},
    )

    async with harness(database, redis_url) as hn:
        hn.deps.http = web.client(
            "api.github.com", "generativelanguage.googleapis.com", "llm.cert.example.org"
        )
        hn.deps.vault = Vault(public_keys={}, keyrings=TEST_KEYRINGS)
        async with hn.app_db(CERT) as db:
            await seed_agents(db, CERT, datetime.now(UTC))
            await db.commit()
        await hn.workflow(CERT, "Nouvelle CVE NVD → investigation", NEW_CVE)

        for cve_id, engine in (
            ("CVE-2026-7001", "gemini-2.5-flash"),
            ("CVE-2026-7002", "llm-interne"),
        ):
            await prefer(engine)  # the switch is a configuration, through the API
            await _publish(database, cve_id)
            assert await hn.dispatch() == 1

    rows = await _sql(
        database,
        "SELECT v.cve_id, a.status, n.content FROM vulnerabilities v "
        "JOIN vulnerability_assessments a ON a.vulnerability_id = v.id "
        "JOIN vulnerability_analyses n ON n.vulnerability_id = v.id ORDER BY v.cve_id",
    )
    assert [(r["cve_id"], r["status"]) for r in rows] == [
        ("CVE-2026-7001", "new"),  # unqualified: the analysts decide
        ("CVE-2026-7002", "new"),
    ]
    for row in rows:
        synthesis = json.loads(row["content"])
        assert synthesis["exploitation_status"] == "poc_public"
        assert synthesis["poc"][0]["url"] == POC  # sourced: a URL read by the PoC agent
    engines = await _sql(
        database,
        "SELECT DISTINCT r.input->>'cve_id' AS cve, r.engine_kind FROM agent_runs r "
        "WHERE r.status = 'succeeded' ORDER BY 1",
    )
    assert [(r["cve"], r["engine_kind"]) for r in engines] == [
        ("CVE-2026-7001", "gemini"),
        ("CVE-2026-7002", "openai_compatible"),
    ]
    flags = await _sql(
        database,
        "SELECT count(*) AS n FROM agent_runs WHERE injection_flags::text LIKE '%uncited%'",
    )
    assert flags[0]["n"] == 0  # every URL cited came from a consulted source
