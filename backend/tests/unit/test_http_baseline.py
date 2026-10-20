from collections.abc import AsyncIterator

import httpx
import pytest
from app.app_factory import create_app
from app.core.access import public_endpoint
from app.core.middleware import API_SECURITY_HEADERS
from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel

from tests.conftest import make_settings


async def test_healthz_reports_service(client: httpx.AsyncClient, audience: str) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": audience}


async def test_security_headers_on_every_response(client: httpx.AsyncClient) -> None:
    for path in ("/healthz", "/does-not-exist"):
        response = await client.get(path)
        for name, value in API_SECURITY_HEADERS.items():
            assert response.headers[name] == value, (path, name)
        assert "server" not in response.headers


async def test_unknown_route_is_problem_json(client: httpx.AsyncClient) -> None:
    response = await client.get("/nope")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["status"] == 404
    assert body["request_id"] == response.headers["x-request-id"]


async def test_request_id_reused_only_when_well_formed(client: httpx.AsyncClient) -> None:
    good = await client.get("/healthz", headers={"x-request-id": "abcdef12-3456"})
    assert good.headers["x-request-id"] == "abcdef12-3456"
    bad = await client.get("/healthz", headers={"x-request-id": "<script>alert(1)</script>"})
    assert bad.headers["x-request-id"] != "<script>alert(1)</script>"
    assert len(bad.headers["x-request-id"]) == 32


async def test_body_over_limit_is_rejected() -> None:

    app = create_app("backoffice", make_settings(max_request_body_bytes=1024))

    @app.post("/upload-test", dependencies=[Depends(public_endpoint)])
    async def upload_test(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(4):
            yield b"x" * 512

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        announced = await c.post("/upload-test", content=b"x" * 2048)
        streamed = await c.post("/upload-test", content=chunks())  # no Content-Length
        accepted = await c.post("/upload-test", content=b"x" * 512)
    assert announced.status_code == 413
    assert streamed.status_code == 413
    assert accepted.json() == {"size": 512}


async def test_validation_errors_do_not_echo_input() -> None:

    app = create_app("backoffice", make_settings())

    class Payload(BaseModel):
        count: int

    @app.post("/echo-test", dependencies=[Depends(public_endpoint)])
    async def echo_test(payload: Payload) -> dict[str, int]:
        return {"count": payload.count}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        response = await c.post("/echo-test", json={"count": "secret-value-123"})
    assert response.status_code == 422
    assert "secret-value-123" not in response.text
    assert response.json()["errors"][0]["loc"] == ["body", "count"]


async def test_unhandled_error_is_generic_500_with_headers() -> None:
    app = create_app("portal", make_settings())

    @app.get("/boom", dependencies=[Depends(public_endpoint)])
    async def boom() -> None:
        raise RuntimeError("internal detail that must not leak")

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        response = await c.get("/boom")
    assert response.status_code == 500
    assert "internal detail" not in response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "x-request-id" in response.headers


@pytest.mark.parametrize(("environment", "exposed"), [("dev", True), ("prod", False)])
async def test_openapi_hidden_in_production(environment: str, exposed: bool) -> None:
    app: FastAPI = create_app("backoffice", make_settings(environment=environment))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        response = await c.get("/api/v1/openapi.json")
    assert (response.status_code == 200) is exposed


def test_portal_does_not_mount_backoffice_api() -> None:
    portal = create_app("portal", make_settings())
    paths = {getattr(route, "path", "") for route in portal.routes}
    assert not any(path.startswith("/api/v1") for path in paths)
