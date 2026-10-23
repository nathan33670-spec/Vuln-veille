"""Exit criterion of phase 7 (PLAN.md), in a real browser against the real API.

Without knowing the target API in advance, an analyst configures a publication
connector from the interface (its secret, URL, authentication, mapping and remote
identifier), pushes a validated bulletin and reads the complete journal. The remote
API is simulated; the ``publish`` worker runs in-process on the queued pushes.
"""

import asyncio
import json
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from app.core.db import create_engine, create_sessionmaker
from app.core.tasks import MemoryTaskQueue
from app.publish.runner import PUSH_TASK, PushDeps, run_push
from app.vault.service import Vault
from tests.conftest import TEST_KEYRINGS, make_settings
from tests.integration.browser import NEEDS_BROWSER, free_port, run_script, served
from tests.integration.conftest import PASSWORDS, Database
from tests.integration.publish_support import (
    Partner,
    seed_all_templates,
    sql,
    validated_bulletin,
)
from tests.integration.seed import WORKSPACE_IDS, create_user

SCRIPT = Path(__file__).with_name("phase7_exit.cjs")
CERT = WORKSPACE_IDS["cert"]

pytestmark = [pytest.mark.integration, NEEDS_BROWSER]


async def _pump(api: FastAPI, deps: PushDeps, database: Database) -> None:
    """The ``publish`` worker: pushes queued by the API run in-process."""
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    queue: MemoryTaskQueue = api.state.tasks
    try:
        while True:
            while queue.sent:
                name, kwargs = queue.sent.pop(0)
                if name == PUSH_TASK:
                    await run_push(
                        create_sessionmaker(engine),
                        deps,
                        uuid.UUID(kwargs["publication_id"]),
                        uuid.UUID(kwargs["workspace_id"]),
                    )
            await asyncio.sleep(0.2)
    finally:
        await engine.dispose()


async def test_phase_7_exit_in_a_browser(
    database: Database, redis_url: str, clean_state: None, tmp_path: Path
) -> None:
    await seed_all_templates(database, redis_url)
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    bulletin = await validated_bulletin(database, CERT, "approved")
    ref = (await sql(database, "SELECT ref FROM bulletins WHERE id = $1", bulletin))[0]["ref"]
    partner = Partner()
    deps = PushDeps(
        make_settings(redis_url=SecretStr(redis_url)),
        Vault(public_keys={}, keyrings=TEST_KEYRINGS),
        MemoryTaskQueue(),
        http=partner.client("api.partner.example"),
    )
    # Generated per run: no credential-looking literal in the repository.
    value = f"partner-{uuid.uuid4().hex}"
    port = free_port()
    async with served(database, redis_url, port) as api:
        pump = asyncio.create_task(_pump(api, deps, database))
        code, report = await run_script(
            str(SCRIPT),
            {
                "base": f"http://localhost:{port}",
                "email": eve.email,
                "password": eve.password,
                "totpSecret": eve.totp_secret,
                "bulletin": str(bulletin),
                "ref": ref,
                "vaultValue": value,
                "artifacts": str(tmp_path),
            },
        )
        pump.cancel()
    assert code == 0, report

    # The remote API received the mapped bulletin with the credential from the vault.
    method, path, headers, body = partner.received[-1]
    assert (method, path) == ("POST", "/v2/advisories")
    assert headers["authorization"] == f"Bearer {value}"
    assert body["reference"] == ref
    assert body["title"] == "RCE dans Exemple"
    # The journal is complete and holds no credential.
    pushes = await sql(
        database, "SELECT status, mode, remote_id, origin FROM publications WHERE NOT is_test"
    )
    assert [tuple(p) for p in pushes] == [("succeeded", "create", "ADV-1", "user")]
    attempts = await sql(database, "SELECT request, response_status FROM publication_attempts")
    assert [a["response_status"] for a in attempts if a["response_status"] == 201]
    assert value not in json.dumps([json.loads(a["request"]) for a in attempts])
