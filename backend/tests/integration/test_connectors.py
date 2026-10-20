"""Connector framework: validation, team isolation, connection tests in the worker."""

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr
from redis.asyncio import Redis

from app.connectors.base import Quotas
from app.connectors.quotas import QuotaExceededError, QuotaGuard
from app.connectors.runtime import check_connector
from tests.conftest import TEST_KEYRING_LINES, make_settings
from tests.connector_fakes import echo_type
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, SeededUser, create_user

pytestmark = pytest.mark.integration

SOURCES = "/workspaces/cert/connectors/source"


@pytest.fixture(autouse=True)
def _echo() -> Iterator[None]:
    with echo_type():
        yield


async def _session(api: Api, user: SeededUser) -> dict[str, str]:
    return {"x-csrf-token": await sign_in(api, user)}


async def _secret(api: Api, headers: dict[str, str], path: str, purpose: str = "source") -> str:
    response = await api.client.post(
        api.url(path),
        json={"name": f"s-{uuid.uuid4().hex[:8]}", "purpose": purpose, "value": "tok-123"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def _cert_analyst(api: Api, database: Database) -> dict[str, str]:
    user = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    return await _session(api, user)


def _worker_settings(database: Database, tmp_path: Path, redis_url: str):  # type: ignore[no-untyped-def]
    for purpose, line in TEST_KEYRING_LINES.items():
        (tmp_path / f"{purpose}.keyring").write_text(line + "\n")
    return make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)),
        redis_url=SecretStr(redis_url),
        vault_keyring_dir=tmp_path,
    )


async def test_workspace_connector_lifecycle_and_worker_check(
    make_api: ApiFactory, database: Database, redis_url: str, tmp_path: Path
) -> None:
    api = await make_api("backoffice")
    headers = await _cert_analyst(api, database)
    secret_id = await _secret(api, headers, "/workspaces/cert/secrets")

    types = await api.client.get(api.url("/connector-types"))
    echo = next(t for t in types.json() if t["kind"] == "test_echo")
    assert echo["cost_class"] == "free_account"
    assert echo["secret_slots"] == [{"name": "token", "label": "Jeton", "required": True}]

    created = await api.client.post(
        api.url(SOURCES),
        json={"kind": "test_echo", "name": "Echo", "secret_refs": {"token": secret_id}},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    connector = created.json()
    assert connector["health"] == "unknown"
    assert connector["egress_domains"] == ["echo.example.org"]
    assert connector["config"] == {"fail": False, "limit": 1}

    usage = await api.client.get(api.url(f"{SOURCES}/{connector['id']}/usage"))
    assert usage.status_code == 200
    assert usage.json()["day"] == 0

    checked = await api.client.post(api.url(f"{SOURCES}/{connector['id']}/check"), headers=headers)
    assert checked.status_code == 202
    assert api.tasks.sent == [
        (
            "collect.connector_check",
            {"connector_id": connector["id"], "workspace_id": str(WORKSPACE_IDS["cert"])},
        )
    ]

    settings = _worker_settings(database, tmp_path, redis_url)
    result = await check_connector(settings, uuid.UUID(connector["id"]), WORKSPACE_IDS["cert"])
    assert result is not None
    assert result.ok
    healthy = (await api.client.get(api.url(f"{SOURCES}/{connector['id']}"))).json()
    assert healthy["health"] == "ok"
    assert healthy["last_success_at"] is not None

    # A VOC task can never reach a CERT connector, even by id.
    assert await check_connector(settings, uuid.UUID(connector["id"]), WORKSPACE_IDS["voc"]) is None

    stale = await api.client.patch(
        api.url(f"{SOURCES}/{connector['id']}"),
        json={"version": 0, "config": {"fail": True}},
        headers=headers,
    )
    assert stale.status_code == 409
    updated = await api.client.patch(
        api.url(f"{SOURCES}/{connector['id']}"),
        json={"version": 1, "config": {"fail": True}},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2
    failed = await check_connector(settings, uuid.UUID(connector["id"]), WORKSPACE_IDS["cert"])
    assert failed is not None
    assert not failed.ok
    degraded = (await api.client.get(api.url(f"{SOURCES}/{connector['id']}"))).json()
    assert degraded["health"] == "degraded"
    assert degraded["last_error"] == "service refused the token"

    in_use = await api.client.delete(
        api.url(f"/workspaces/cert/secrets/{secret_id}"), headers=headers
    )
    assert in_use.status_code == 409
    assert in_use.json()["detail"] == "secret_in_use"
    deleted = await api.client.delete(api.url(f"{SOURCES}/{connector['id']}"), headers=headers)
    assert deleted.status_code == 204
    freed = await api.client.delete(
        api.url(f"/workspaces/cert/secrets/{secret_id}"), headers=headers
    )
    assert freed.status_code == 204


async def test_secret_references_stay_in_scope_and_purpose(
    make_api: ApiFactory, database: Database
) -> None:
    voc = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    voc_api = await make_api("backoffice")
    voc_headers = await _session(voc_api, voc)
    voc_secret = await _secret(voc_api, voc_headers, "/workspaces/voc/secrets")
    global_secret = await _secret(voc_api, voc_headers, "/admin/secrets")

    api = await make_api("backoffice")
    headers = await _cert_analyst(api, database)
    llm_secret = await _secret(api, headers, "/workspaces/cert/secrets", purpose="llm")

    async def create(refs: dict[str, str], **extra: object) -> tuple[int, str | None]:
        body = {"kind": "test_echo", "name": "Echo", "secret_refs": refs, **extra}
        response = await api.client.post(api.url(SOURCES), json=body, headers=headers)
        return response.status_code, response.json().get("detail")

    assert await create({"token": voc_secret}) == (422, "secret_not_found")
    assert await create({"token": global_secret}) == (422, "secret_not_found")
    assert await create({"token": llm_secret}) == (422, "secret_purpose_mismatch")
    assert await create({}) == (422, "missing_secret")
    assert await create({"token": llm_secret, "other": llm_secret}) == (422, "unknown_secret_slot")
    status, detail = await create({}, config={"fail": True, "url": "http://10.0.0.1"})
    assert (status, detail) == (422, "invalid_config")
    invalid = await api.client.post(
        api.url(SOURCES),
        json={"kind": "test_echo", "name": "x", "config": {"limit": "http://169.254.169.254"}},
        headers=headers,
    )
    assert "169.254" not in invalid.text  # field errors never echo submitted values
    wrong_family = await api.client.post(
        api.url("/workspaces/cert/connectors/publish"),
        json={"kind": "test_echo", "name": "x"},
        headers=headers,
    )
    assert wrong_family.json()["detail"] == "wrong_family"
    unknown = await api.client.post(
        api.url(SOURCES), json={"kind": "no_such_kind", "name": "x"}, headers=headers
    )
    assert unknown.json()["detail"] == "unknown_kind"

    # Global connectors are for administrators; CERT has none.
    forbidden = await api.client.get(api.url("/admin/connectors/source"))
    assert forbidden.status_code == 403
    global_created = await voc_api.client.post(
        voc_api.url("/admin/connectors/source"),
        json={"kind": "test_echo", "name": "Global echo", "secret_refs": {"token": global_secret}},
        headers=voc_headers,
    )
    assert global_created.status_code == 201, global_created.text
    voc_view = await voc_api.client.get(voc_api.url("/workspaces/cert/connectors/source"))
    assert voc_view.status_code == 404


async def test_quota_windows(redis_url: str) -> None:
    redis = Redis.from_url(redis_url)
    try:
        guard = QuotaGuard(redis, uuid.uuid4(), Quotas(requests_per_minute=2, requests_per_day=3))
        await guard.consume()
        await guard.consume()
        with pytest.raises(QuotaExceededError) as exc:
            await guard.consume()
        assert exc.value.window == "minute"
        usage = await guard.usage()
        assert usage["minute"] == 2  # the refused request did not count
        assert usage["day"] == 2
        unlimited = QuotaGuard(redis, uuid.uuid4(), Quotas())
        for _ in range(5):
            await unlimited.consume()
    finally:
        await redis.aclose()
