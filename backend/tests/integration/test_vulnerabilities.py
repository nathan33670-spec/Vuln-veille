"""Shared vulnerabilities qualified per team (ADR-024), watch scope, sources."""

import json
import uuid

import asyncpg
import pytest
from pydantic import SecretStr
from sqlalchemy import select, update

from app.catalog.fetch import fetch_cve
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context, set_context
from app.vulns.models import Assessment
from app.watch.models import CollectedItem
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.nvd_fakes import FakeNvd, nvd_item

pytestmark = pytest.mark.integration

LOG4SHELL = "CVE-2021-44228"


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _catalogue_cve(database: Database, cve_id: str = LOG4SHELL) -> None:
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, cpe_criteria, base_score, severity, "
        "published_at, first_seen_at, synced_at, sources, kev) VALUES ($1, $2, $3, 10.0, "
        "'CRITICAL', now(), now(), now(), ARRAY['nvd'], '{\"date_added\": \"2021-12-10\"}')",
        cve_id,
        "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
        ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
    )


async def _teams(
    make_api: ApiFactory, database: Database
) -> tuple[Api, dict[str, str], Api, dict[str, str], uuid.UUID]:
    voc = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    cert = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    voc_api, cert_api = await make_api("backoffice"), await make_api("backoffice")
    return (
        voc_api,
        {"x-csrf-token": await sign_in(voc_api, voc)},
        cert_api,
        {"x-csrf-token": await sign_in(cert_api, cert)},
        cert.id,
    )


async def test_shared_record_qualified_per_team(make_api: ApiFactory, database: Database) -> None:
    await _catalogue_cve(database)
    voc_api, voc_h, cert_api, cert_h, cert_user = await _teams(make_api, database)

    tech = await voc_api.client.post(
        voc_api.url("/technologies"),
        json={
            "vendor": "apache",
            "product": "log4j",
            "display_name": "Apache Log4j",
            "cpe_prefixes": ["cpe:2.3:a:apache:log4j"],
        },
        headers=voc_h,
    )
    assert tech.status_code == 201, tech.text
    scope = await voc_api.client.put(
        voc_api.url("/workspaces/voc/watch-scope"),
        json={
            "version": 0,
            "technology_ids": [tech.json()["id"]],
            "always_include_kev": False,
            "include_unscored": "exclude",
        },
        headers=voc_h,
    )
    assert scope.status_code == 200, scope.text
    in_scope = await voc_api.client.get(
        voc_api.url("/cves"), params={"scope_of": "voc", "decision": "in_scope"}
    )
    assert [c["cve_id"] for c in in_scope.json()["items"]] == [LOG4SHELL]
    assert in_scope.json()["items"][0]["scope_reasons"] == ["technology:apache:log4j:cpe"]
    assert (
        await cert_api.client.get(cert_api.url("/cves"), params={"scope_of": "voc"})
    ).status_code == 404

    created = await voc_api.client.post(
        voc_api.url("/workspaces/voc/vulnerabilities"), json={"cve_id": LOG4SHELL}, headers=voc_h
    )
    assert created.status_code == 201, created.text
    vuln = created.json()
    ref = vuln["ref"]
    assert ref.startswith("VV-")
    assert ref.endswith("-0001")
    assert vuln["title"].startswith(f"{LOG4SHELL} : Apache Log4j2 JNDI")
    assert [t["matched_by"] for t in vuln["technologies"]] == ["cpe"]
    assert vuln["kev"] is True
    again = await cert_api.client.post(
        cert_api.url("/workspaces/cert/vulnerabilities"), json={"cve_id": LOG4SHELL}, headers=cert_h
    )
    assert again.status_code == 409
    assert again.json()["detail"] == f"exists:{ref}"  # one record per CVE
    events = await _sql(database, "SELECT type FROM outbox_events WHERE type = 'vuln.created'")
    assert len(events) == 1

    voc_path = f"/workspaces/voc/vulnerabilities/{ref}"
    no_priority = await voc_api.client.put(
        voc_api.url(voc_path + "/assessment"),
        json={"version": 0, "status": "qualified"},
        headers=voc_h,
    )
    assert no_priority.json()["detail"] == "priority_required"
    qualified = await voc_api.client.put(
        voc_api.url(voc_path + "/assessment"),
        json={
            "version": 0,
            "status": "qualified",
            "priority": "P1",
            "severity": "CRITICAL",
            "rationale": "**Exploited in the wild.**",
        },
        headers=voc_h,
    )
    assert qualified.status_code == 200, qualified.text
    illegal = await voc_api.client.put(
        voc_api.url(voc_path + "/assessment"),
        json={"version": 1, "status": "rejected"},
        headers=voc_h,
    )
    assert illegal.json()["detail"] == "invalid_transition"

    queue = await cert_api.client.get(
        cert_api.url("/vulnerabilities"), params={"team": "cert", "state": "unqualified"}
    )
    assert [v["ref"] for v in queue.json()["items"]] == [ref]
    other = queue.json()["items"][0]["assessments"]
    assert [(a["workspace"], a["status"], a["priority"]) for a in other] == [
        ("voc", "qualified", "P1")
    ]
    assert (
        await voc_api.client.get(
            voc_api.url("/vulnerabilities"), params={"team": "voc", "state": "unqualified"}
        )
    ).json()["items"] == []

    forbidden = await cert_api.client.put(
        cert_api.url(voc_path + "/assessment"),
        json={"version": 1, "status": "triage"},
        headers=cert_h,
    )
    assert forbidden.status_code == 404
    adopted = await cert_api.client.post(
        cert_api.url(f"/workspaces/cert/vulnerabilities/{ref}/assessment/adopt"),
        json={"from_workspace": "voc"},
        headers=cert_h,
    )
    assert adopted.status_code == 200, adopted.text
    cert_view = {a["workspace"]: a for a in adopted.json()["assessments"]}
    assert cert_view["cert"]["priority"] == "P1"
    assert cert_view["cert"]["adopted_from"] == "voc"
    assert cert_view["cert"]["rationale"] == "**Exploited in the wild.**"

    not_member = await cert_api.client.put(
        cert_api.url(f"/workspaces/cert/vulnerabilities/{ref}/assessment"),
        json={"version": 1, "assignee_id": str(uuid.uuid4())},
        headers=cert_h,
    )
    assert not_member.json()["detail"] == "assignee_not_analyst"
    assigned = await cert_api.client.put(
        cert_api.url(f"/workspaces/cert/vulnerabilities/{ref}/assessment"),
        json={"version": 1, "assignee_id": str(cert_user)},
        headers=cert_h,
    )
    assert assigned.status_code == 200, assigned.text
    mine = await cert_api.client.get(
        cert_api.url("/vulnerabilities"), params={"team": "cert", "assigned_to_me": "true"}
    )
    assert mine.json()["total"] == 1

    # RLS: even a CERT session cannot write the VOC assessment directly.
    engine = create_engine(database.dsn("vv_app", PASSWORDS.app))
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(WORKSPACE_IDS["cert"],))
            result = await db.execute(
                update(Assessment)
                .where(Assessment.workspace_id == WORKSPACE_IDS["voc"])
                .values(priority="P4")
            )
            assert result.rowcount == 0  # type: ignore[attr-defined]
            visible = (await db.execute(select(Assessment.workspace_id))).scalars().all()
            assert set(visible) == {WORKSPACE_IDS["voc"], WORKSPACE_IDS["cert"]}  # readable
    finally:
        await engine.dispose()

    timeline = (await cert_api.client.get(cert_api.url(f"/vulnerabilities/{ref}"))).json()[
        "timeline"
    ]
    assert [e["type"] for e in timeline] == [
        "vulnerability.created",
        "assessment.updated",
        "assessment.adopted",
        "assessment.updated",
    ]


async def test_comments_stay_private_and_evidence_is_shared(
    make_api: ApiFactory, database: Database
) -> None:
    voc_api, voc_h, cert_api, cert_h, _ = await _teams(make_api, database)
    created = await voc_api.client.post(
        voc_api.url("/workspaces/voc/vulnerabilities"),
        json={"title": "Acme Portal SQL injection (no CVE yet)", "aliases": ["ACME-2026-01"]},
        headers=voc_h,
    )
    assert created.status_code == 201, created.text
    ref = created.json()["ref"]
    voc_path = f"/workspaces/voc/vulnerabilities/{ref}"

    comment = await voc_api.client.post(
        voc_api.url(voc_path + "/comments"),
        json={"body": "Call the vendor\u202e tomorrow"},
        headers=voc_h,
    )
    assert comment.status_code == 201
    assert comment.json()["body"] == "Call the vendor tomorrow"  # control characters removed
    assert (await cert_api.client.get(cert_api.url(voc_path + "/comments"))).status_code == 404
    cert_comments = await cert_api.client.get(
        cert_api.url(f"/workspaces/cert/vulnerabilities/{ref}/comments")
    )
    assert cert_comments.json() == []

    bad_url = await voc_api.client.post(
        voc_api.url(voc_path + "/evidence"),
        json={"url": "javascript:alert(1)", "kind": "poc"},
        headers=voc_h,
    )
    assert bad_url.status_code == 422
    evidence = await voc_api.client.post(
        voc_api.url(voc_path + "/evidence"),
        json={
            "url": "https://github.com/acme/poc",
            "title": "PoC <script>alert(1)</script>",
            "kind": "poc",
            "note": "Not executed: read only.",
        },
        headers=voc_h,
    )
    assert evidence.status_code == 201, evidence.text
    seen_by_cert = (await cert_api.client.get(cert_api.url(f"/vulnerabilities/{ref}"))).json()
    assert [(e["workspace"], e["kind"], e["trust"]) for e in seen_by_cert["evidence"]] == [
        ("voc", "poc", "untrusted")
    ]
    assert (
        seen_by_cert["evidence"][0]["title"] == "PoC <script>alert(1)</script>"
    )  # data, not markup

    # An item the VOC collected but did not cite stays invisible to the CERT.
    engine = create_engine(database.dsn("vv_app", PASSWORDS.app))
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            await set_context(db, workspace_ids=(WORKSPACE_IDS["voc"],))
            from datetime import UTC, datetime  # noqa: PLC0415

            from app.watch.collect import store_item  # noqa: PLC0415

            await store_item(
                db,
                WORKSPACE_IDS["voc"],
                source_type="rss",
                now=datetime.now(UTC),
                url="https://blog.example/private",
                title="private",
            )
            await db.commit()
            await set_context(db, workspace_ids=(WORKSPACE_IDS["cert"],))
            titles = (await db.execute(select(CollectedItem.title))).scalars().all()
    finally:
        await engine.dispose()
    assert titles == ["PoC <script>alert(1)</script>"]

    cert_cannot_remove = await cert_api.client.delete(
        cert_api.url(
            f"/workspaces/cert/vulnerabilities/{ref}/evidence/{seen_by_cert['evidence'][0]['id']}"
        ),
        headers=cert_h,
    )
    assert cert_cannot_remove.status_code == 404


async def test_manual_cve_is_fetched_by_the_worker(
    make_api: ApiFactory, database: Database
) -> None:
    voc = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api = await make_api("backoffice")
    headers = {"x-csrf-token": await sign_in(api, voc)}
    created = await api.client.post(
        api.url("/workspaces/voc/vulnerabilities"),
        json={"cve_id": "CVE-2026-4242"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["title"] == "CVE-2026-4242"
    assert api.tasks.sent == [("collect.cve_fetch", {"cve_id": "CVE-2026-4242"})]

    await _sql(
        database,
        "INSERT INTO connectors (id, family, kind, name, config, egress_domains) "
        "VALUES ($1, 'source', 'nvd', 'NVD', '{}', ARRAY['services.nvd.nist.gov'])",
        uuid.uuid4(),
    )
    fake = FakeNvd()
    fake.put(nvd_item("CVE-2026-4242"))
    settings = make_settings(
        database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker))
    )
    assert await fetch_cve(settings, "CVE-2026-4242", http=fake.client())
    detail = (await api.client.get(api.url(f"/vulnerabilities/{created.json()['ref']}"))).json()
    assert detail["title"].startswith("CVE-2026-4242 : Remote code execution")
    assert detail["cve"]["severity"] == "HIGH"
    events = await _sql(database, "SELECT type FROM outbox_events ORDER BY id")
    assert [e["type"] for e in events] == ["vuln.created"]  # the fetch announces nothing


async def test_sources_and_technology_curation(make_api: ApiFactory, database: Database) -> None:
    voc_api, voc_h, cert_api, cert_h, _ = await _teams(make_api, database)
    insecure = await voc_api.client.post(
        voc_api.url("/workspaces/voc/sources"),
        json={"name": "Feed", "config": {"type": "rss", "url": "http://insecure.example/feed"}},
        headers=voc_h,
    )
    assert insecure.status_code == 422
    source = await voc_api.client.post(
        voc_api.url("/workspaces/voc/sources"),
        json={
            "name": "CERT-FR",
            "config": {"type": "rss", "url": "https://www.cert.ssi.gouv.fr/feed/"},
            "tags": ["gouv", "fr"],
        },
        headers=voc_h,
    )
    assert source.status_code == 201, source.text
    assert (await cert_api.client.get(cert_api.url("/workspaces/cert/sources"))).json() == []
    assert (await cert_api.client.get(cert_api.url("/workspaces/voc/sources"))).status_code == 404

    a = (
        await voc_api.client.post(
            voc_api.url("/technologies"),
            json={
                "vendor": "microsoft",
                "product": "exchange_server",
                "display_name": "Exchange Server",
                "cpe_prefixes": ["cpe:2.3:a:microsoft:exchange_server"],
            },
            headers=voc_h,
        )
    ).json()
    b = (
        await cert_api.client.post(
            cert_api.url("/technologies"),
            json={"vendor": "microsoft", "product": "exchange", "display_name": "MS Exchange"},
            headers=cert_h,
        )
    ).json()
    found = await cert_api.client.get(cert_api.url("/technologies"), params={"q": "exchnge"})
    assert {t["id"] for t in found.json()} >= {a["id"]}  # fuzzy search
    not_admin = await cert_api.client.post(
        cert_api.url(f"/technologies/{b['id']}/merge"), json={"into": a["id"]}, headers=cert_h
    )
    assert not_admin.status_code == 403
    merged = await voc_api.client.post(
        voc_api.url(f"/technologies/{b['id']}/merge"), json={"into": a["id"]}, headers=voc_h
    )
    assert merged.status_code == 200, merged.text
    assert "MS Exchange" in merged.json()["aliases"]
    hidden = await voc_api.client.get(voc_api.url("/technologies"), params={"q": "exchange"})
    assert [t["id"] for t in hidden.json()] == [a["id"]]

    await _catalogue_cve(database, "CVE-2026-7777")
    suggestions = await voc_api.client.get(
        voc_api.url("/technologies/cpe-suggestions"), params={"q": "log4"}
    )
    assert suggestions.json()[0]["cpe_prefix"] == "cpe:2.3:a:apache:log4j"
    audit = await _sql(
        database, "SELECT details FROM audit_events WHERE action = 'technology.merged'"
    )
    assert json.loads(audit[0]["details"])["into"] == a["id"]
