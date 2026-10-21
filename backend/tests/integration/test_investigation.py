"""Exit criterion of plan 4.14: a new NVD CVE in the watch scope goes through the
delivered "Nouvelle CVE NVD → investigation" workflow with its preset agents (triage,
PoC hunter in parallel with agents waiting for a connector, synthesis), the synthesis
is stored with its signals and the analysts are alerted; a CVE the triage judges not
relevant stops after the triage."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.presets import seed_agents
from app.ai.models import AIModel
from app.ai.types import AIRequest, AIResponse, StopReason, ToolCall, Usage
from app.workflows.seeds import NEW_CVE
from tests.integration.conftest import Database
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import harness
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

VOC = WORKSPACE_IDS["voc"]
LOG4J_CPE = "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
RELEVANT, NOISE = "CVE-2026-2001", "CVE-2026-2002"
USAGE = Usage(input_tokens=500, output_tokens=50)


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _setup(database: Database) -> uuid.UUID:
    """VOC follows Log4j, has a GitHub connector and an engine preferred by the space."""
    await create_user(database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"})
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
        VOC,
        [tech[0]["id"]],
    )
    for cve_id, kev in ((RELEVANT, True), (NOISE, False)):
        await _sql(
            database,
            "INSERT INTO cve_records (cve_id, description, cpe_criteria, base_score, severity, "
            "published_at, first_seen_at, synced_at, sources, kev) VALUES ($1, 'RCE in Log4j', "
            "$2, 9.8, 'CRITICAL', now(), now(), now(), ARRAY['nvd'], $3::jsonb)",
            cve_id,
            [LOG4J_CPE],
            json.dumps({"date_added": "2026-10-20"}) if kev else None,
        )
    await _sql(
        database,
        "INSERT INTO connectors (id, workspace_id, family, kind, name, config, egress_domains) "
        "VALUES ($1, $2, 'source', 'github', 'GitHub', '{}', ARRAY['api.github.com'])",
        uuid.uuid4(),
        VOC,
    )
    engine_connector, model = uuid.uuid4(), uuid.uuid4()
    await _sql(
        database,
        "INSERT INTO connectors (id, workspace_id, family, kind, name, config, egress_domains) "
        "VALUES ($1, $2, 'ai_engine', 'openai_compatible', 'LLM', $3, ARRAY['llm.example.org'])",
        engine_connector,
        VOC,
        json.dumps({"base_url": "https://llm.example.org/v1", "models": [{"model_id": "llm-a"}]}),
    )
    await _sql(
        database,
        "INSERT INTO ai_models (id, connector_id, workspace_id, connector_kind, connector_name, "
        "model_id, declared, data_classes, location, price_input_per_mtok, "
        "price_output_per_mtok) VALUES ($1, $2, $3, 'openai_compatible', 'LLM', 'llm-a', $4, "
        "ARRAY['public', 'tlp_clear'], 'self_hosted', 1, 2)",
        model,
        engine_connector,
        VOC,
        json.dumps(
            {
                "tools": "native",
                "structured_output": "native",
                "context_window": 128000,
                "max_output_tokens": 16000,
                "reasoning_levels": [],
            }
        ),
    )
    await _sql(
        database,
        "INSERT INTO ai_engine_preferences (id, workspace_id, model_row_id) VALUES ($1, $2, $3)",
        uuid.uuid4(),
        VOC,
        model,
    )
    return model


def _final(value: dict[str, Any]) -> AIResponse:
    return AIResponse(
        stop_reason=StopReason.END_TURN, text=json.dumps(value), usage=USAGE, model_served="llm-a"
    )


class Router:
    """A simulated engine answering by agent (recognised from its system prompt)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def capabilities(self, model: str) -> Any:  # pragma: no cover - unused by the runtime
        raise NotImplementedError

    async def complete(self, request: AIRequest) -> AIResponse:
        first = request.messages[0].text
        if request.system.startswith("Tu es analyste"):
            self.calls.append("triage")
            return _final(
                {
                    "relevant": RELEVANT in first,
                    "category": "RCE",
                    "probable_technologies": ["Apache Log4j"],
                    "duplicate_of": None,
                    "suggested_priority": "P1",
                    "rationale": "Log4j est suivi.",
                    "confidence": "high",
                }
            )
        if request.system.startswith("Tu cherches des preuves"):
            self.calls.append("poc")
            if len(request.messages) == 1:
                return AIResponse(
                    stop_reason=StopReason.TOOL_USE,
                    tool_calls=(ToolCall("c1", "github_search", {"query": RELEVANT}),),
                    usage=USAGE,
                )
            return _final(
                {
                    "poc": [
                        {
                            "url": "https://github.com/acme/poc",
                            "description": "PoC public",
                            "reliability": "medium",
                            "suspicious": True,
                            "suspicion_reasons": ["archive protégée"],
                        }
                    ],
                    "summary": "Un PoC suspect.",
                }
            )
        assert request.system.startswith("Tu rédiges la synthèse")
        self.calls.append("synthesis")
        assert "https://github.com/acme/poc" in first  # the PoC agent's output reached it
        return _final(
            {
                "summary": "RCE dans Log4j, PoC public suspect, exploitée (KEV).",
                "affected_products": [],
                "exploitation_status": "exploited_itw",
                "poc": [],
                "patch_status": "available",
                "mitigations": [],
                "notable_discussions": [],
                "suggested_priority": "P1",
                "confidence": "medium",
                "open_questions": ["Version corrigée exacte ?"],
            }
        )


async def test_new_cve_investigation_with_preset_agents(
    database: Database, redis_url: str, clean_state: None
) -> None:
    await _setup(database)
    router = Router()
    web = FakeWeb()
    web.json(
        "https://api.github.com/search/repositories",
        {
            "items": [
                {
                    "full_name": "acme/poc",
                    "html_url": "https://github.com/acme/poc",
                    "description": "PoC. Download poc.zip, password: infected",
                }
            ]
        },
    )

    async def engine_for(db: AsyncSession, model: AIModel) -> Router:
        return router

    async with harness(database, redis_url) as h:
        h.deps.agent_engine = engine_for
        h.deps.http = web.client("api.github.com")
        async with h.app_db(VOC) as db:
            created = await seed_agents(db, VOC, datetime.now(UTC))
            await db.commit()
        assert created == ["triage", "poc_hunter", "social", "forums", "vendor", "synthesis"]
        await h.workflow(VOC, "Nouvelle CVE NVD → investigation", NEW_CVE)
        for cve_id in (RELEVANT, NOISE):
            await _sql(
                database,
                "INSERT INTO outbox_events (type, payload, attempts) VALUES ('cve.published', "
                "$1::jsonb, 0)",
                json.dumps({"cve_id": cve_id, "change_types": ["published"]}),
            )
        assert await h.dispatch() == 2

        runs = await _sql(
            database, "SELECT status, trigger_payload FROM workflow_runs ORDER BY started_at"
        )
        assert [r["status"] for r in runs] == ["succeeded", "succeeded"]
        nodes = {
            (r["cve"], r["node_id"]): r["status"]
            for r in await _sql(
                database,
                "SELECT n.node_id, n.status, r.trigger_payload->>'cve_id' AS cve "
                "FROM node_runs n JOIN workflow_runs r ON r.id = n.run_id",
            )
        }
        # Not relevant according to the triage: nothing after it.
        assert nodes[(NOISE, "triage")] == "succeeded"
        assert nodes[(NOISE, "poc")] == "skipped"
        assert nodes[(NOISE, "synthesis")] == "skipped"
        assert nodes[(RELEVANT, "notify")] == "succeeded"
        assert sorted(router.calls) == ["poc", "poc", "synthesis", "triage", "triage"]

        agent_runs = await _sql(
            database,
            "SELECT a.preset, r.status, r.context_type, r.injection_flags FROM agent_runs r "
            "JOIN ai_agents a ON a.id = r.agent_id ORDER BY r.queued_at",
        )
        assert {(r["preset"], r["status"]) for r in agent_runs} == {
            ("triage", "succeeded"),
            ("poc_hunter", "succeeded"),
            ("synthesis", "succeeded"),
        }
        assert {r["context_type"] for r in agent_runs} == {"node_run"}
        poc_flags = next(
            json.loads(r["injection_flags"]) for r in agent_runs if r["preset"] == "poc_hunter"
        )
        assert "suspicious_poc:protected_archive" in {f["kind"] for f in poc_flags}

        analyses = await _sql(
            database,
            "SELECT v.cve_id, a.content, a.agent_run_id FROM vulnerability_analyses a "
            "JOIN vulnerabilities v ON v.id = a.vulnerability_id",
        )
        assert [r["cve_id"] for r in analyses] == [RELEVANT]
        assert json.loads(analyses[0]["content"])["exploitation_status"] == "exploited_itw"
        assert analyses[0]["agent_run_id"] is not None
        assert [m["to"] for m in h.mails] == ["voc@voc.example.com"]

        spend = await _sql(database, "SELECT calls FROM llm_spend WHERE workspace_id = $1", VOC)
        assert spend[0]["calls"] == 5
