"""Shared by the browser tests (phase exit criteria): a built front-end (back-office or
portal) and the real API served on localhost with the production CSP, and the skip
conditions.

Needs a Chromium and the Playwright Node package, given by VV_E2E_CHROMIUM and
VV_E2E_PLAYWRIGHT, and the built front-end (pnpm --filter @vv/backoffice build, or
@vv/portal for the portal).
"""

import asyncio
import json
import os
import shutil
import socket
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

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
PORTAL_DIST = BACKEND_DIR.parent / "frontend" / "apps" / "portal" / "dist"
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
NEEDS_PORTAL_BROWSER = pytest.mark.skipif(
    not (
        CHROMIUM and PLAYWRIGHT and shutil.which("node") and (PORTAL_DIST / "index.html").exists()
    ),
    reason="browser test: set VV_E2E_CHROMIUM, VV_E2E_PLAYWRIGHT and build the portal",
)

Audience = Literal["backoffice", "portal"]
Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def site(api: FastAPI, dist: Path = DIST) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """The API under /api, the built single-page app elsewhere, with the CSP."""
    root = dist.resolve()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        if scope["path"].startswith("/api/"):
            await api(scope, receive, send)
            return
        relative = scope["path"].lstrip("/")
        target = (dist / relative).resolve()
        if not relative or not target.is_file() or root not in target.parents:
            target = dist / "index.html"

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
async def served(
    database: Database, redis_url: str, port: int, audience: Audience = "backoffice"
) -> AsyncIterator[FastAPI]:
    here, elsewhere = f"http://localhost:{port}", "http://localhost:1"
    portal = audience == "portal"
    settings = make_settings(
        database_url_app=SecretStr(database.dsn("vv_app", PASSWORDS.app)),
        database_url_portal=SecretStr(database.dsn("vv_portal", PASSWORDS.portal)),
        redis_url=SecretStr(redis_url),
        backoffice_origin=elsewhere if portal else here,
        portal_origin=here if portal else elsewhere,
    )
    api = create_app(audience, settings, mailer=MemoryMailer(), tasks=MemoryTaskQueue())
    async with api.router.lifespan_context(api):
        config = uvicorn.Config(
            site(api, PORTAL_DIST if portal else DIST),
            host="127.0.0.1",
            port=port,
            lifespan="off",
            log_level="warning",
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
