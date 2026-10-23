"""Portal delivery (phase 8, 8B): the platform branding (Q46), each user's choice of
e-mail (Q44), the bulletin sent at publication and update with its PDF to the allowed
organisations only, whatever the TLP shown (Q45), a notice at withdrawal, sent once;
the PDF export of the portal."""

import base64
import io
import uuid

import pytest
from PIL import Image
from pydantic import SecretStr

from app.bulletins.publication_events import PUBLICATION_MAIL_TASK
from app.core.db import create_engine, create_sessionmaker
from app.core.mailer import Mail
from app.portal.mailing import MailDeps, send_publication_mail
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.publish_support import (
    Client,
    login,
    seed_all_templates,
    validated_bulletin,
)
from tests.integration.seed import WORKSPACE_IDS, create_org, create_user

pytestmark = pytest.mark.integration

CERT = WORKSPACE_IDS["cert"]


def _png() -> str:
    out = io.BytesIO()
    Image.new("RGB", (400, 120), (20, 60, 160)).save(out, format="PNG")
    return base64.b64encode(out.getvalue()).decode()


async def _client(make_api: ApiFactory, database: Database, email: str, org: uuid.UUID) -> Api:
    user = await create_user(database.admin_dsn, email, user_type="client", client_org=org)
    api = await make_api("portal")
    csrf = await sign_in(api, user)
    api.client.headers["x-csrf-token"] = csrf
    return api


async def _publish(e: Client, bulletin: uuid.UUID) -> None:
    current = await e.call("GET", f"/workspaces/cert/bulletins/{bulletin}")
    await e.call(
        "POST", f"/workspaces/cert/bulletins/{bulletin}/publish", {"version": current["version"]}
    )


async def test_bulletins_by_email_with_pdf_and_branding(
    make_api: ApiFactory, database: Database, redis_url: str, clean_state: None
) -> None:
    await seed_all_templates(database, redis_url)
    acme = await create_org(database.admin_dsn, "Acme")
    beta = await create_org(database.admin_dsn, "Beta")
    ana = await create_user(
        database.admin_dsn, "ana@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    eve = await create_user(
        database.admin_dsn, "eve@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    admin, e = await login(make_api, ana), await login(make_api, eve)

    # Branding, by a platform administrator; the logo is re-encoded.
    branding = await admin.call("GET", "/admin/branding")
    branding = await admin.call(
        "PUT", "/admin/branding", {"issuer_name": "CERT Exemple", "version": branding["version"]}
    )
    await admin.call(
        "PUT", "/admin/branding/logo", {"data_base64": "PHN2Zz4=", "version": branding["version"]},
        422,
    )  # fmt: skip
    branding = await admin.call(
        "PUT", "/admin/branding/logo", {"data_base64": _png(), "version": branding["version"]}
    )
    assert branding == {"issuer_name": "CERT Exemple", "has_logo": True, "version": 3}
    await e.call("GET", "/admin/branding", status=403)

    # Each client user chooses; Bob (Acme) does not want e-mails.
    alice = await _client(make_api, database, "alice@acme.example", acme)
    bob = await _client(make_api, database, "bob@acme.example", acme)
    carol = await _client(make_api, database, "carol@beta.example", beta)
    for api in (alice, carol):
        response = await api.client.put(
            api.url("/me/notifications"), json={"email_bulletins": True}
        )
        assert response.json() == {"email_bulletins": True}, response.text
    assert (await bob.client.get(bob.url("/me/notifications"))).json() == {"email_bulletins": False}
    shown = (await alice.client.get(alice.url("/branding"))).json()
    assert shown["issuer_name"] == "CERT Exemple"
    logo = await alice.client.get(alice.url("/branding/logo"))
    assert logo.headers["content-type"] == "image/png"

    sent: list[Mail] = []
    deps = MailDeps(make_settings(redis_url=SecretStr(redis_url)), sent.append)
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    sessions = create_sessionmaker(engine)

    async def deliver() -> list[Mail]:
        name, kwargs = e.api.tasks.sent.pop()
        assert name == PUBLICATION_MAIL_TASK
        sent.clear()
        count = await send_publication_mail(
            sessions, deps, uuid.UUID(kwargs["event_id"]), uuid.UUID(kwargs["workspace_id"])
        )
        assert count == len(sent)
        # Delivered once: a redelivery of the task sends nothing.
        assert (
            await send_publication_mail(
                sessions, deps, uuid.UUID(kwargs["event_id"]), uuid.UUID(kwargs["workspace_id"])
            )
            == 0
        )
        return list(sent)

    try:
        # GREEN for Acme only: Alice, not Bob (no e-mail), not Carol (Beta).
        green = await validated_bulletin(
            database, CERT, "approved", title="Faille Acme", audience=[acme]
        )
        await _publish(e, green)
        mails = await deliver()
        assert [m.to for m in mails] == ["alice@acme.example"]
        mail = mails[0]
        assert mail.subject.startswith("[TLP:GREEN] CERT-")
        assert mail.subject.endswith("Faille Acme")
        assert "<h1>Faille Acme</h1>" in (mail.html or "")
        assert "CERT Exemple" in mail.body
        assert mail.attachments[0].data.startswith(b"%PDF-")

        # AMBER for Beta: full content and PDF to Carol only (Q45).
        amber = await validated_bulletin(
            database, CERT, "approved", title="Faille Beta", tlp="AMBER", audience=[beta]
        )
        await _publish(e, amber)
        mails = await deliver()
        assert [m.to for m in mails] == ["carol@beta.example"]
        assert mails[0].attachments
        assert "Faille Beta" in (mails[0].html or "")

        # An update published again: « Mise à jour ».
        current = await e.call("GET", f"/workspaces/cert/bulletins/{green}")
        fields = {**current["current"]["fields"], "summary": "Correctif disponible."}
        current = await e.call(
            "POST", f"/workspaces/cert/bulletins/{green}/revisions",
            {"fields": fields, "base_rev_no": current["current"]["rev_no"]}, 201,
        )  # fmt: skip
        await e.call("POST", f"/workspaces/cert/bulletins/{green}/approve",
                     {"version": current["version"]})  # fmt: skip
        await _publish(e, green)
        mails = await deliver()
        assert [m.subject.split("] ")[1].split(" :")[0] for m in mails] == ["Mise à jour"]

        # Withdrawal: a short notice to the same readers, without the content.
        current = await e.call("GET", f"/workspaces/cert/bulletins/{green}")
        await e.call(
            "POST", f"/workspaces/cert/bulletins/{green}/withdraw",
            {"reason": "Doublon", "version": current["version"]},
        )  # fmt: skip
        mails = await deliver()
        assert [(m.to, m.attachments, m.html) for m in mails] == [("alice@acme.example", (), None)]
        assert "retiré" in mails[0].body
    finally:
        await engine.dispose()

    # PDF export from the portal: allowed organisation only.
    pdf = await carol.client.get(carol.url(f"/bulletins/{amber}/export"), params={"format": "pdf"})
    assert pdf.status_code == 200, pdf.text
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")
    denied = await alice.client.get(
        alice.url(f"/bulletins/{amber}/export"), params={"format": "pdf"}
    )
    assert denied.status_code == 404
