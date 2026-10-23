"""Exit criterion of phase 8 (PLAN.md), in a real browser against the real portal API.

A client consults the bulletins meant for the organisation, in the portal: list, search,
detail with its history, PDF export, printing, the e-mail preference, the issuer's
branding. Next to them the CERT publishes bulletins the client must never see (another
organisation's, RED, a draft, an update not yet published again): neither the list,
nor the search, nor a direct link shows them. The non-leak tests of the API and the
database (``test_portal_bulletins.py``) prove the rest.
"""

import io
import uuid
from pathlib import Path

import pytest
from PIL import Image

from app.portal.branding import normalize_logo
from tests.integration.browser import NEEDS_PORTAL_BROWSER, free_port, run_script, served
from tests.integration.conftest import ApiFactory, Database
from tests.integration.publish_support import (
    Client,
    login,
    seed_all_templates,
    sql,
    validated_bulletin,
)
from tests.integration.seed import WORKSPACE_IDS, create_org, create_user

SCRIPT = Path(__file__).with_name("phase8_exit.cjs")
CERT = WORKSPACE_IDS["cert"]

pytestmark = [pytest.mark.integration, NEEDS_PORTAL_BROWSER]


async def _publish(e: Client, bulletin: uuid.UUID) -> None:
    current = await e.call("GET", f"/workspaces/cert/bulletins/{bulletin}")
    await e.call(
        "POST", f"/workspaces/cert/bulletins/{bulletin}/publish", {"version": current["version"]}
    )


def _logo() -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (300, 100), (20, 60, 160)).save(out, format="PNG")
    return normalize_logo(out.getvalue())


async def test_phase_8_exit_in_a_browser(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None, tmp_path: Path
) -> None:
    await seed_all_templates(database, redis_url)
    acme = await create_org(database.admin_dsn, "Acme")
    beta = await create_org(database.admin_dsn, "Beta")
    alice = await create_user(
        database.admin_dsn, "alice@acme.example", user_type="client", client_org=acme,
        with_totp=True,
    )  # fmt: skip
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    await sql(
        database,
        "UPDATE platform_branding SET issuer_name = 'CERT Exemple', logo_png = $1",
        _logo(),
    )
    e = await login(make_api, eve)

    async def published(title: str, tlp: str, audience: list[uuid.UUID] | None = None) -> str:
        bulletin = await validated_bulletin(
            database, CERT, "approved", title=title, tlp=tlp, audience=audience
        )
        await _publish(e, bulletin)
        return str(bulletin)

    everyone = await published("Faille pour tous", "GREEN")
    for_acme = await published("Faille réservée Acme", "AMBER", [acme])
    for_beta = await published("Faille réservée Beta", "AMBER", [beta])
    red = await published("Faille rouge", "RED", [acme])
    await validated_bulletin(database, CERT, "draft", title="Brouillon interne")
    # An update in progress on the bulletin for everyone: not published again.
    current = await e.call("GET", f"/workspaces/cert/bulletins/{everyone}")
    fields = {**current["current"]["fields"], "title": "Titre en cours de révision"}
    await e.call(
        "POST", f"/workspaces/cert/bulletins/{everyone}/revisions",
        {"fields": fields, "base_rev_no": current["current"]["rev_no"]}, 201,
    )  # fmt: skip

    port = free_port()
    async with served(database, redis_url, port, "portal"):
        code, report = await run_script(
            str(SCRIPT),
            {
                "base": f"http://localhost:{port}",
                "email": alice.email,
                "password": alice.password,
                "totpSecret": alice.totp_secret,
                "visible": {"everyone": everyone, "acme": for_acme},
                "hidden": {"beta": for_beta, "red": red},
                "hiddenTitles": [
                    "Faille réservée Beta",
                    "Faille rouge",
                    "Brouillon interne",
                    "Titre en cours de révision",
                ],
                "artifacts": str(tmp_path),
            },
        )
    assert code == 0, report
    # The choice made in the portal is Alice's own.
    rows = await sql(
        database, "SELECT user_id, email_bulletins FROM portal_notification_preferences"
    )
    assert [tuple(r) for r in rows] == [(alice.id, True)]
