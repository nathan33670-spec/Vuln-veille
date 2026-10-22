"""X discovery layer 2 and the coverage indicator (plan 4.18): the social media agent
finds post URLs with the engine's web search, reads them through the official oEmbed,
and only posts both cited and actually read count; the indicator is compared with an
analyst's hand check."""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.presets import seed_agents
from app.ai.agents.runtime import AgentDeps, execute_run
from app.ai.models import AIModel
from app.ai.types import AIRequest, AIResponse, StopReason, ToolCall, Usage, WebResult
from app.connectors.types.x_reader import OEMBED
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from app.core.tasks import MemoryTaskQueue
from app.vault.service import Vault
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]
CVE = "CVE-2026-5001"
REAL = "https://x.com/researcher/status/1850000000001"
MADE_UP = "https://x.com/nobody/status/1850000000002"


@dataclass
class SocialModel:
    """Discovers with the web search, reads both URLs, then cites both."""

    searches: list[AIRequest] = field(default_factory=list)
    turn: int = 0

    def capabilities(self, model: str) -> Any:  # pragma: no cover - unused by the runtime
        raise NotImplementedError

    async def complete(self, request: AIRequest) -> AIResponse:
        usage = Usage(input_tokens=200, output_tokens=30)
        if request.web_search is not None:
            self.searches.append(request)
            return AIResponse(
                stop_reason=StopReason.END_TURN,
                text=f"{MADE_UP}\nhttps://evil.example/not-x",
                web_results=(WebResult(REAL, "post"),),
                usage=Usage(input_tokens=50, output_tokens=10, web_search_requests=1),
            )
        self.turn += 1
        if self.turn == 1:
            return AIResponse(
                stop_reason=StopReason.TOOL_USE,
                tool_calls=(ToolCall("c1", "x_discover", {"cve_id": CVE}),),
                usage=usage,
            )
        if self.turn == 2:
            return AIResponse(
                stop_reason=StopReason.TOOL_USE,
                tool_calls=(
                    ToolCall("c2", "x_read", {"url": REAL}),
                    ToolCall("c3", "x_read", {"url": MADE_UP}),
                ),
                usage=usage,
            )
        discussion = {"platform": "x", "takeaway": "PoC confirmé"}
        return AIResponse(
            stop_reason=StopReason.END_TURN,
            text=json.dumps(
                {
                    "exploitation_reports": [{**discussion, "url": REAL}],
                    "researchers": ["@researcher"],
                    "notable_discussions": [{**discussion, "url": MADE_UP}],
                    "summary": "Un chercheur signale un PoC.",
                }
            ),
            usage=usage,
        )


def _oembed(request: httpx.Request) -> tuple[int, Any]:
    if request.url.params["url"] != REAL:
        return 404, {"error": "not found"}
    return 200, {
        "author_url": "https://twitter.com/researcher",
        "html": "<blockquote><p>PoC for CVE-2026-5001 works</p></blockquote>",
    }


async def _post(api: Api, headers: dict[str, str], path: str, body: Any, status: int) -> Any:
    response = await api.client.post(api.url(path), json=body, headers=headers)
    assert response.status_code == status, response.text
    return response.json()


async def test_x_layer_two_and_coverage_indicator(
    make_api: ApiFactory, database: Database, redis_url: str
) -> None:
    user = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, user)}
    await _post(
        api,
        h,
        "/workspaces/cert/connectors/ai_engine",
        {
            "kind": "openai_compatible",
            "name": "LLM",
            "config": {
                "base_url": "https://llm.cert.example.org/v1",
                "models": [{"model_id": "llm-a", "web_search": True}],
            },
        },
        201,
    )
    models = {m["model_id"]: m for m in (await api.client.get(api.url("/ai-models"))).json()}
    assert models["llm-a"]["declared"]["web_search"] is True
    await api.client.put(
        api.url("/workspaces/cert/ai-engine"),
        json={"model_row_id": models["llm-a"]["id"]},
        headers=h,
    )
    await _post(
        api,
        h,
        "/workspaces/cert/connectors/source",
        {"kind": "x_reader", "name": "X", "config": {"engine_web_search": True}},
        201,
    )

    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)),
        database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
        redis_url=SecretStr(redis_url),
    )
    app_engine = create_engine(settings.database_url_app.get_secret_value())
    worker_engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with create_sessionmaker(app_engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(CERT,))
            await seed_agents(db, CERT, datetime.now(UTC))
            await db.commit()
        agents = (await api.client.get(api.url("/workspaces/cert/agents"))).json()
        social = next(a for a in agents if a["preset"] == "social")
        queued = await _post(
            api, h, f"/workspaces/cert/agents/{social['id']}/test", {"input": {"cve_id": CVE}}, 202
        )

        model = SocialModel()
        web = FakeWeb()
        web.routes[OEMBED] = _oembed

        async def engine_for(db: AsyncSession, row: AIModel) -> SocialModel:
            return model

        deps = AgentDeps(
            settings,
            Vault(public_keys={}, keyrings=TEST_KEYRINGS),
            clock=lambda: datetime.now(UTC),
            tasks=MemoryTaskQueue(),
            http=web.client("publish.x.com"),
            engine_for=engine_for,
        )
        async with create_sessionmaker(worker_engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(CERT,))
            assert await execute_run(db, deps, uuid.UUID(queued["run_id"])) == "succeeded"
    finally:
        await app_engine.dispose()
        await worker_engine.dispose()

    # Layer 2: one web search on the CVE only, restricted to X; only post URLs kept.
    assert len(model.searches) == 1
    search = model.searches[0]
    assert search.web_search is not None
    assert search.web_search.allowed_domains == ("x.com", "twitter.com")
    assert search.messages[0].text == f'"{CVE}" site:x.com OR site:twitter.com'
    detail = (
        await api.client.get(api.url(f"/workspaces/cert/agent-runs/{queued['run_id']}"))
    ).json()
    discover = next(
        s
        for s in detail["steps"]
        if s["type"] == "tool_result" and s["payload"]["name"] == "x_discover"
    )
    listed = discover["payload"]["content"]["documents"][0]
    assert listed["x_post_urls"] == [REAL, MADE_UP]
    assert listed["layers"] == {"collected": 0, "web_search": 2}
    purposes = [s["payload"].get("purpose") for s in detail["steps"] if s["type"] == "llm_call"]
    assert purposes.count("web_search") == 1
    assert detail["turns"] == 3  # the search is not a turn of the loop

    # Only the post cited and actually read counts.
    coverage = (await api.client.get(api.url("/workspaces/cert/x-coverage"))).json()
    assert coverage["investigated"] == 1
    assert coverage["with_x_discussion"] == 1
    assert coverage["coverage_rate"] == 1.0

    # Compared with the analysts' hand check.
    bad = await api.client.put(
        api.url(f"/workspaces/cert/x-coverage/checks/{CVE}"),
        json={"has_discussion": True, "urls": ["https://example.com/a"]},
        headers=h,
    )
    assert bad.status_code == 422
    checked = await api.client.put(
        api.url(f"/workspaces/cert/x-coverage/checks/{CVE}"),
        json={"has_discussion": True, "urls": [REAL.replace("x.com", "twitter.com")]},
        headers=h,
    )
    assert checked.status_code == 200, checked.text
    assert checked.json()["urls"] == [REAL]
    coverage = (await api.client.get(api.url("/workspaces/cert/x-coverage"))).json()
    assert coverage["sample"]["recall"] == 1.0
    assert coverage["sample"]["compared"] == 1
