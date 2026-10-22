"""Shared by the browser tests (phase exit criteria): the built back-office and the real
API served on localhost with the production CSP, and the skip condition.

Needs a Chromium and the Playwright Node package, given by VV_E2E_CHROMIUM and
VV_E2E_PLAYWRIGHT, and the built front-end (pnpm --filter @vv/backoffice build).
"""

import asyncio
import json
import os
import shutil
import socket
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr
from starlette.responses import FileResponse

from app.app_factory import create_app
from app.core.mailer import MemoryMailer
from app.core.tasks import MemoryTaskQueue
from tests.conftest import make_settings
from tests.integration.conftest import BACKEND_DIR, PASSWORDS, Database

CHROMIUM = os.environ.get("VV_E2E_CHROMIUM", "")
PLAYWRIGHT = os.environ.get("VV_E2E_PLAYWRIGHT", "")
DIST = BACKEND_DIR.parent / "frontend" / "apps" / "backoffice" / "dist"
# The production policy (deploy/caddy/Caddyfile), without upgrade-insecure-requests.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; "
    "trusted-types dompurify"
)
SCRIPT_TIMEOUT_S = 240
NEEDS_BROWSER = pytest.mark.skipif(
    not (CHROMIUM and PLAYWRIGHT and shutil.which("node") and (DIST / "index.html").exists()),
    reason="browser test: set VV_E2E_CHROMIUM, VV_E2E_PLAYWRIGHT and build the back-office",
)

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def site(api: FastAPI) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """The API under /api, the built single-page app elsewhere, with the CSP."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        if scope["path"].startswith("/api/"):
            await api(scope, receive, send)
            return
        relative = scope["path"].lstrip("/")
        target = (DIST / relative).resolve()
        if not relative or not target.is_file() or DIST.resolve() not in target.parents:
            target = DIST / "index.html"

        async def with_csp(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [
                    *message.get("headers", []),
                    (b"content-security-policy", CSP.encode()),
                ]
            await send(message)

        await FileResponse(target)(scope, receive, with_csp)

    return app


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@asynccontextmanager
async def served(database: Database, redis_url: str, port: int) -> AsyncIterator[FastAPI]:
    settings = make_settings(
        database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
        database_url_portal=SecretStr(database.dsn("vv_portal", PASSWORDS.portal)),
        redis_url=SecretStr(redis_url),
        backoffice_origin=f"http://localhost:{port}",
        portal_origin="http://localhost:1",
    )
    api = create_app("backoffice", settings, mailer=MemoryMailer(), tasks=MemoryTaskQueue())
    async with api.router.lifespan_context(api):
        config = uvicorn.Config(
            site(api), host="127.0.0.1", port=port, lifespan="off", log_level="warning"
        )
        server = uvicorn.Server(config)
        serving = asyncio.create_task(server.serve())
        while not server.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an event
            await asyncio.sleep(0.05)
        try:
            yield api
        finally:
            server.should_exit = True
            await serving


async def run_script(script: str, config: dict[str, Any]) -> tuple[int, str]:
    """Runs a browser script (``node script '<json>'``): its exit code and output."""
    browser = await asyncio.create_subprocess_exec(
        "node",
        script,
        json.dumps({**config, "chromium": CHROMIUM, "playwright": PLAYWRIGHT}),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    async with asyncio.timeout(SCRIPT_TIMEOUT_S):
        output, _ = await browser.communicate()
    return browser.returncode or 0, output.decode()
