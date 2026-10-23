"""A self-hosted OpenAI-compatible model on the private network (ADR-032): the team
declares it, asks for its private range, a platform administrator approves, and a
question asked from the interface is answered by the ``ai`` worker; before the
approval the request never leaves. The approved range also reaches smokescreen's
configuration (``allow_ranges``)."""

import json
import uuid
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from redis.asyncio import Redis

from app.ai.probe import PROBE_TASK, run_probe
from app.connectors.egress_acl import approved_ranges, render_config
from app.net.safe_http import EgressPolicy, SafeHttpClient
from tests.conftest import TEST_KEYRING_LINES, make_settings
from tests.integration.conftest import PASSWORDS, ApiFactory, Database
from tests.integration.publish_support import Client, login, sql
from tests.integration.seed import create_user
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

ENGINES = "/workspaces/cert/connectors/ai_engine"
LLM_ADDRESS = "10.20.0.5"


def _llm() -> FakeWeb:
    web = FakeWeb()

    def complete(request: httpx.Request) -> tuple[int, object]:
        body = json.loads(request.content)
        assert body["model"] == "llama3"
        assert body["messages"][-1] == {"role": "user", "content": "Dis bonjour."}
        return 200, {
            "id": "c1",
            "model": "llama3:8b",
            "choices": [
                {"message": {"role": "assistant", "content": "Bonjour !"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 21, "completion_tokens": 3},
        }

    web.routes["https://llm.cert.internal:11434/v1/chat/completions"] = complete
    return web


def _private_http(web: FakeWeb):  # type: ignore[no-untyped-def]
    """The worker's client with the connector's real policy; the name resolves to a
    private address, as on the team's network."""

    async def resolve(host: str, port: int) -> list[str]:
        return [LLM_ADDRESS]

    def factory(policy: EgressPolicy) -> SafeHttpClient:
        return SafeHttpClient(
            policy, proxy=None, resolver=resolve, transport=httpx.MockTransport(web.handler)
        )

    return factory


async def _probe(e: Client, connector: str, worker_settings, web: FakeWeb) -> dict[str, object]:  # type: ignore[no-untyped-def]
    queued = await e.call(
        "POST", f"{ENGINES}/{connector}/probe",
        {"model_id": "llama3", "prompt": "Dis bonjour."}, 202,
    )  # fmt: skip
    name, kwargs = e.api.tasks.sent.pop()
    assert name == PROBE_TASK
    assert "prompt" not in kwargs  # the question stays out of the task broker
    await run_probe(
        worker_settings,
        uuid.UUID(kwargs["probe_id"]),
        uuid.UUID(kwargs["connector_id"]),
        uuid.UUID(kwargs["workspace_id"]),
        http_factory=_private_http(web),
    )
    return dict(await e.call("GET", f"{ENGINES}/{connector}/probe/{queued['probe_id']}"))


async def test_a_local_model_answers_once_its_private_range_is_approved(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None, tmp_path: Path
) -> None:
    ana = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    admin, e = await login(make_api, ana), await login(make_api, eve)
    for purpose, line in TEST_KEYRING_LINES.items():
        (tmp_path / f"{purpose}.keyring").write_text(line + "\n")
    worker_settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)),
        redis_url=SecretStr(redis_url),
        vault_keyring_dir=tmp_path,
    )

    connector = await e.call(
        "POST", ENGINES,
        {
            "kind": "openai_compatible",
            "name": "LLM interne",
            "config": {
                "base_url": "https://llm.cert.internal:11434/v1",
                "data_classes": ["public", "tlp_clear", "tlp_green", "tlp_amber"],
                "models": [{"model_id": "llama3", "tools": "emulated",
                            "structured_output": "none", "max_output_tokens": 2048}],
            },
            "secret_refs": {},
        },
        201,
    )  # fmt: skip
    assert connector["egress_domains"] == ["llm.cert.internal"]
    web = _llm()

    # Not approved: the private address is refused before anything is sent.
    refused = await _probe(e, connector["id"], worker_settings, web)
    assert refused["status"] == "failed"
    assert str(refused["error"]).startswith("egress: ")
    assert web.requests == []
    await e.call(
        "POST", f"{ENGINES}/{connector['id']}/probe", {"model_id": "gpt-4", "prompt": "x"}, 422
    )

    # The team asks for the range; a platform administrator approves.
    network = f"{ENGINES}/{connector['id']}/private-network"
    pending = await e.call(
        "POST", network, {"cidrs": ["10.20.0.0/16"], "reason": "LLM du CERT"}, 201
    )
    assert await approved_ranges(worker_settings) == set()
    queue = await admin.call("GET", "/admin/private-network-requests")
    assert [(q["workspace_slug"], q["hosts"]) for q in queue] == [("cert", ["llm.cert.internal"])]
    await admin.call(
        "POST", f"/admin/private-network-requests/{pending['id']}/decision", {"approve": True}
    )

    answered = await _probe(e, connector["id"], worker_settings, web)
    assert answered["status"] == "succeeded", answered
    assert answered["answer"] == "Bonjour !"
    assert answered["model_served"] == "llama3:8b"
    assert (answered["input_tokens"], answered["output_tokens"]) == (21, 3)
    assert len(web.requests) == 1

    # The question is not kept once answered; the call counts in the team's budget.
    redis = Redis.from_url(redis_url)
    try:
        keys = [k async for k in redis.scan_iter("ai_probe:*")]
        assert keys
        stored = [await redis.get(k) or b"" for k in keys]
        assert all(b"Dis bonjour" not in value for value in stored)
    finally:
        await redis.aclose()
    spend = await sql(database, "SELECT calls, output_tokens FROM llm_spend")
    assert [tuple(r) for r in spend] == [(1, 3)]

    # Smokescreen's configuration lets the approved range through, and nothing else.
    ranges = await approved_ranges(worker_settings)
    assert ranges == {"10.20.0.0/16"}
    assert render_config(ranges).endswith("allow_ranges:\n  - 10.20.0.0/16\n")

    # Another team cannot read the probe, nor ask the CERT's engine.
    victor = await create_user(
        database.admin_dsn, "victor@voc.example.com", workspaces={"voc": "analyst"},
        with_totp=True,
    )  # fmt: skip
    v = await login(make_api, victor)
    await v.call(
        "POST", f"/workspaces/voc/connectors/ai_engine/{connector['id']}/probe",
        {"model_id": "llama3", "prompt": "x"}, 404,
    )  # fmt: skip
    audit = await sql(
        database, "SELECT details FROM audit_events WHERE action = 'ai.engine_probed'"
    )
    assert all("Dis bonjour" not in json.dumps(json.loads(r["details"])) for r in audit)
