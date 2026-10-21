"""AI engines as connectors: model catalogue, verified capabilities, preferred engine."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import SecretStr

from app.ai.engines.gemini import GeminiConfig, GeminiConnector
from app.ai.preferences import resolve
from app.ai.types import AIConfigurationError
from app.connectors.base import ConnectorContext
from app.connectors.models import Connector
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.unit.test_ai_engines import GEMINI_URL, _gemini_server
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]


async def _team(make_api: ApiFactory, database: Database, slug: str) -> tuple[Api, dict[str, str]]:
    user = await create_user(
        database.admin_dsn,
        f"{slug}@{slug}.example.com",
        workspaces={slug: "analyst"},
        with_totp=True,
    )
    api = await make_api("backoffice")
    return api, {"x-csrf-token": await sign_in(api, user)}


async def _secret(api: Api, headers: dict[str, str], path: str) -> str:
    response = await api.client.post(
        api.url(path),
        json={"name": f"llm-{uuid.uuid4().hex[:6]}", "purpose": "llm", "value": "key-not-real"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _models(api_models: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {m["model_id"]: m for m in api_models}


async def test_engine_catalogue_preferences_and_isolation(
    make_api: ApiFactory, database: Database
) -> None:
    voc, voc_h = await _team(make_api, database, "voc")  # VOC analysts are platform admins
    cert, cert_h = await _team(make_api, database, "cert")

    key = await _secret(voc, voc_h, "/admin/secrets")
    created = await voc.client.post(
        voc.url("/admin/connectors/ai_engine"),
        json={"kind": "gemini", "name": "Gemini gratuit", "secret_refs": {"api_key": key}},
        headers=voc_h,
    )
    assert created.status_code == 201, created.text
    gemini_connector = created.json()
    assert gemini_connector["quotas"]["requests_per_day"] == 250
    refused = await voc.client.post(
        voc.url("/admin/connectors/ai_engine"),
        json={
            "kind": "gemini",
            "name": "Gemini ambre",
            "secret_refs": {"api_key": key},
            "config": {"data_classes": ["public", "tlp_amber"]},
        },
        headers=voc_h,
    )
    assert refused.status_code == 422  # Q6: the free tier only receives public data

    llm = await cert.client.post(
        cert.url("/workspaces/cert/connectors/ai_engine"),
        json={
            "kind": "openai_compatible",
            "name": "LLM interne",
            "config": {
                "base_url": "https://llm.cert.example.org/v1",
                "models": [{"model_id": "mistral-small", "tools": "emulated"}],
                "data_classes": ["public", "tlp_clear", "tlp_green", "tlp_amber"],
            },
        },
        headers=cert_h,
    )
    assert llm.status_code == 201, llm.text
    assert llm.json()["egress_domains"] == ["llm.cert.example.org"]

    cert_models = _models((await cert.client.get(cert.url("/ai-models"))).json())
    assert set(cert_models) == {"gemini-2.5-flash", "mistral-small"}
    assert cert_models["gemini-2.5-flash"]["scope"] == "global"
    assert cert_models["gemini-2.5-flash"]["verified"] is None
    assert cert_models["mistral-small"]["declared"]["tools"] == "emulated"
    voc_models = _models((await voc.client.get(voc.url("/ai-models"))).json())
    assert set(voc_models) == {"gemini-2.5-flash"}  # the CERT engine stays private
    gemini_row = cert_models["gemini-2.5-flash"]["id"]
    cert_row = cert_models["mistral-small"]["id"]

    # Platform default: administrators only, global engines only.
    assert (
        await cert.client.put(
            cert.url("/admin/ai-engine"), json={"model_row_id": gemini_row}, headers=cert_h
        )
    ).status_code == 403
    assert (
        await voc.client.put(
            voc.url("/admin/ai-engine"), json={"model_row_id": cert_row}, headers=voc_h
        )
    ).status_code == 404
    platform = await voc.client.put(
        voc.url("/admin/ai-engine"), json={"model_row_id": gemini_row}, headers=voc_h
    )
    assert platform.status_code == 200, platform.text

    view = (await cert.client.get(cert.url("/workspaces/cert/ai-engine"))).json()
    assert (view["source"], view["effective"]["model_id"]) == ("platform", "gemini-2.5-flash")
    own = await cert.client.put(
        cert.url("/workspaces/cert/ai-engine"), json={"model_row_id": cert_row}, headers=cert_h
    )
    assert (own.json()["source"], own.json()["effective"]["model_id"]) == (
        "workspace",
        "mistral-small",
    )
    assert (
        await voc.client.put(
            voc.url("/workspaces/voc/ai-engine"), json={"model_row_id": cert_row}, headers=voc_h
        )
    ).status_code == 404

    # The worker resolves the same choice, inside the workspace's context.
    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker))
    )
    engine = create_engine(settings.database_url_worker.get_secret_value())
    sessions = create_sessionmaker(engine)
    try:
        async with sessions() as db:
            init_context(db)
            await set_context(db, workspace_ids=(CERT,))
            assert (await resolve(db, CERT)).model.model_id == "mistral-small"

        inherited = await cert.client.delete(cert.url("/workspaces/cert/ai-engine"), headers=cert_h)
        assert inherited.json()["source"] == "platform"

        # A disabled engine is not usable anymore, at any level.
        disable = await voc.client.patch(
            voc.url(f"/admin/connectors/ai_engine/{gemini_connector['id']}"),
            json={"version": gemini_connector["version"], "enabled": False},
            headers=voc_h,
        )
        assert disable.status_code == 200, disable.text
        assert (
            await cert.client.put(
                cert.url("/workspaces/cert/ai-engine"),
                json={"model_row_id": gemini_row},
                headers=cert_h,
            )
        ).status_code == 422
        async with sessions() as db:
            init_context(db)
            await set_context(db, workspace_ids=(CERT,))
            with pytest.raises(AIConfigurationError, match="platform_engine_unavailable"):
                await resolve(db, CERT)

        # Capability verification by the worker (fake Gemini behind SafeHttpClient).
        web = FakeWeb()
        web.routes[GEMINI_URL] = _gemini_server
        async with sessions() as db:
            init_context(db)
            connector = await db.get(Connector, uuid.UUID(gemini_connector["id"]))
            assert connector is not None
            type_ = GeminiConnector()
            ctx = ConnectorContext(
                connector_id=connector.id,
                workspace_id=None,
                config=GeminiConfig.model_validate(connector.config),
                secrets={"api_key": "key-not-real"},
                http=web.client("generativelanguage.googleapis.com"),
            )
            result = await type_.health_check(ctx)
            assert result.ok, result.message
            await type_.on_checked(db, connector, result, datetime.now(UTC))
            await db.commit()
    finally:
        await engine.dispose()

    checked = _models((await cert.client.get(cert.url("/ai-models"))).json())["gemini-2.5-flash"]
    assert checked["verified"]["tools"] == "native"
    assert checked["checks"]["checks"]["tools"] is True
    assert checked["verified_at"] is not None

    audit = (await voc.client.get(voc.url("/admin/audit"))).json()["items"]
    assert {"ai_engine.platform_set"} <= {e["action"] for e in audit}
