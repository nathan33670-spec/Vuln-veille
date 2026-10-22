"""Engine evaluation bench end to end (plan 4.16): reference cases validated by the
analysts, one run per model on a simulated engine, the comparative report, its budget,
and the report cited when the preferred engine changes."""

import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import asyncpg
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.runtime import AgentDeps
from app.ai.evaluation.runner import run_evaluation
from app.ai.models import AIModel
from app.ai.types import AIRequest, AIResponse, StopReason, Usage
from app.core.db import create_engine, create_sessionmaker
from app.core.tasks import MemoryTaskQueue
from app.vault.service import Vault
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]
SCHEMA = {
    "type": "object",
    "properties": {
        "exploitation_status": {"type": "string"},
        "patch_status": {"type": "string"},
    },
    "required": ["exploitation_status", "patch_status"],
    "additionalProperties": False,
}
CASES = {
    "CVE-2026-3001": {"exploitation_status": "exploited_itw", "patch_status": "available"},
    "CVE-2026-3002": {"exploitation_status": "poc_public", "patch_status": "none"},
}


class Engine:
    """llm-a always answers "unknown"; llm-b knows the reference answers."""

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id

    def capabilities(self, model: str) -> Any:  # pragma: no cover - unused by the runtime
        raise NotImplementedError

    async def complete(self, request: AIRequest) -> AIResponse:
        cve_id = next(c for c in CASES if c in request.messages[0].text)
        if self.model_id == "llm-b":
            answer = CASES[cve_id]
        else:
            answer = {"exploitation_status": "unknown", "patch_status": "unknown"}
        return AIResponse(
            stop_reason=StopReason.END_TURN,
            text=json.dumps(answer),
            usage=Usage(input_tokens=1000, output_tokens=100),  # 0.003 USD
            model_served=self.model_id,
        )


async def _post(api: Api, headers: dict[str, str], path: str, body: Any, status: int) -> Any:
    response = await api.client.post(api.url(path), json=body, headers=headers)
    assert response.status_code == status, response.text
    return response.json()


async def test_evaluation_bench(make_api: ApiFactory, database: Database, redis_url: str) -> None:
    user = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, user)}
    prices = {"price_input_per_mtok": "2", "price_output_per_mtok": "10"}
    await _post(
        api,
        h,
        "/workspaces/cert/connectors/ai_engine",
        {
            "kind": "openai_compatible",
            "name": "LLM interne",
            "config": {
                "base_url": "https://llm.cert.example.org/v1",
                "models": [{"model_id": "llm-a", **prices}, {"model_id": "llm-b", **prices}],
            },
        },
        201,
    )
    models = {m["model_id"]: m["id"] for m in (await api.client.get(api.url("/ai-models"))).json()}
    await api.client.put(
        api.url("/workspaces/cert/ai-engine"), json={"model_row_id": models["llm-a"]}, headers=h
    )
    agent = await _post(
        api,
        h,
        "/workspaces/cert/agents",
        {
            "name": "Statuts",
            "spec": {"system_prompt": "Donne les statuts.", "output_schema": SCHEMA},
        },
        201,
    )

    # Reference cases, validated by an analyst.
    for cve_id, expected in CASES.items():
        await _post(
            api,
            h,
            "/workspaces/cert/ai-evaluation/cases",
            {"cve_id": cve_id, "expected": expected},
            201,
        )
    duplicate = await _post(
        api, h, "/workspaces/cert/ai-evaluation/cases", {"cve_id": "CVE-2026-3001"}, 409
    )
    assert duplicate["detail"] == "case_exists"
    cases = (await api.client.get(api.url("/workspaces/cert/ai-evaluation/cases"))).json()
    assert [c["cve_id"] for c in cases] == list(CASES)
    assert cases[0]["validated_by"] == str(user.id)

    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)),
        redis_url=SecretStr(redis_url),
    )
    engine = create_engine(settings.database_url_worker.get_secret_value())
    sessions = create_sessionmaker(engine)

    async def engine_for(db: AsyncSession, model: AIModel) -> Engine:
        return Engine(model.model_id)

    deps = AgentDeps(
        settings,
        Vault(public_keys={}, keyrings=TEST_KEYRINGS),
        clock=lambda: datetime.now(UTC),
        tasks=MemoryTaskQueue(),
        engine_for=engine_for,
    )

    async def evaluate(model_id: str, max_cost: str = "5") -> dict[str, Any]:
        started = await _post(
            api,
            h,
            "/workspaces/cert/ai-evaluation/runs",
            {"agent_id": agent["id"], "model_row_id": models[model_id], "max_cost_usd": max_cost},
            202,
        )
        name, kwargs = api.tasks.sent.pop()
        assert (name, kwargs["run_id"]) == ("ai.evaluation_run", started["id"])
        await run_evaluation(sessions, deps, uuid.UUID(started["id"]), CERT)
        return dict(
            (
                await api.client.get(
                    api.url(f"/workspaces/cert/ai-evaluation/runs/{started['id']}")
                )
            ).json()
        )

    try:
        baseline = await evaluate("llm-a")
        candidate = await evaluate("llm-b")
        assert baseline["status"] == candidate["status"] == "succeeded"
        assert baseline["metrics"]["accuracy"] == 0.0
        assert candidate["metrics"]["accuracy"] == 1.0
        assert candidate["metrics"]["schema_valid_rate"] == 1.0
        assert Decimal(candidate["metrics"]["cost_per_case_usd"]) == Decimal("0.003")
        assert [r["cve_id"] for r in candidate["results"]] == list(CASES)

        report = (
            await api.client.get(
                api.url("/workspaces/cert/ai-evaluation/compare"),
                params={"baseline": baseline["id"], "candidate": candidate["id"]},
            )
        ).json()
        assert report["metrics"]["accuracy"] == {"baseline": 0.0, "candidate": 1.0, "delta": 1.0}
        assert report["cases"][0]["baseline"]["accuracy"] == 0.0

        # The bench stops at its own budget.
        capped = await evaluate("llm-b", max_cost="0.001")
        assert capped["status"] == "budget_exceeded"
        assert len(capped["results"]) == 1

        # The runs are traced like any agent run, as evaluations.
        runs = (await api.client.get(api.url("/workspaces/cert/agent-runs"))).json()
        assert {r["context_type"] for r in runs} == {"evaluation"}
        assert {r["model_served"] for r in runs} == {"llm-a", "llm-b"}
    finally:
        await engine.dispose()

    # Switching the preferred engine cites the report (optional, Q26).
    wrong = await api.client.put(
        api.url("/workspaces/cert/ai-engine"),
        json={"model_row_id": models["llm-a"], "evaluation_id": candidate["id"]},
        headers=h,
    )
    assert wrong.status_code == 422
    assert wrong.json()["detail"] == "evaluation_mismatch"
    switched = await api.client.put(
        api.url("/workspaces/cert/ai-engine"),
        json={"model_row_id": models["llm-b"], "evaluation_id": candidate["id"]},
        headers=h,
    )
    assert switched.status_code == 200, switched.text
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        audit = await conn.fetchrow(
            "SELECT details FROM audit_events WHERE action = 'ai_engine.workspace_set' "
            "ORDER BY id DESC LIMIT 1"
        )
    finally:
        await conn.close()
    assert audit is not None
    assert json.loads(audit["details"])["evaluation_id"] == candidate["id"]

    # Another workspace sees none of it.
    voc_user = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    voc = await make_api("backoffice")
    await sign_in(voc, voc_user)
    hidden = await voc.client.get(voc.url(f"/workspaces/cert/ai-evaluation/runs/{candidate['id']}"))
    assert hidden.status_code == 404
    assert (await voc.client.get(voc.url("/workspaces/voc/ai-evaluation/runs"))).json() == []
