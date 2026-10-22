"""Bulletin templates through the API: delivered templates, selection on real
vulnerabilities, versions, server-side preview, settings, workspace isolation."""

import copy
import json
import uuid
from datetime import UTC, datetime

import asyncpg
import pytest

from app.bulletins.seeds import SEEDS, seed_templates
from tests.integration.conftest import Api, ApiFactory, Database
from tests.integration.helpers import sign_in
from tests.integration.seed import WORKSPACE_IDS, create_user
from tests.integration.workflow_harness import harness

pytestmark = pytest.mark.integration

VOC = WORKSPACE_IDS["voc"]


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _vulnerability(database: Database, cve_id: str, *, kev: bool, score: float) -> uuid.UUID:
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, base_score, severity, kev, cwes, "
        "first_seen_at, synced_at) VALUES ($1, 'RCE <script>x</script>', $2, $3, $4::jsonb, "
        "ARRAY['CWE-78'], now(), now())",
        cve_id,
        score,
        "CRITICAL" if score >= 9 else "HIGH",
        json.dumps({"date_added": "2026-10-20"}) if kev else None,
    )
    vulnerability = uuid.uuid4()
    await _sql(
        database,
        "INSERT INTO vulnerabilities (id, cve_id, title, first_seen_at, origin) "
        "VALUES ($1, $2, $3, now(), 'user')",
        vulnerability,
        cve_id,
        f"Faille {cve_id}",
    )
    return vulnerability


async def _seeded(database: Database, redis_url: str) -> None:
    async with harness(database, redis_url) as engine:
        for slug in ("voc", "cert"):
            async with engine.app_db(WORKSPACE_IDS[slug]) as db:
                await seed_templates(db, WORKSPACE_IDS[slug], slug, datetime.now(UTC))
                await db.commit()


async def test_templates_selection_preview_and_versions(
    make_api: ApiFactory, database: Database, redis_url: str
) -> None:
    await _seeded(database, redis_url)
    user = await create_user(
        database.admin_dsn, "voc@voc.example.com", workspaces={"voc": "analyst"}, with_totp=True
    )
    api: Api = await make_api("backoffice")
    h = {"x-csrf-token": await sign_in(api, user)}
    base = api.url("/workspaces/voc")

    # Delivered templates: generic FR (the default) and EN, and the urgent one.
    listed = (await api.client.get(f"{base}/bulletin-templates")).json()
    assert {(t["seed_key"], t["status"], t["is_default"]) for t in listed} == {
        ("generic_fr", "active", True),
        ("generic_en", "active", False),
        ("urgent_fr", "active", False),
    }
    settings = (await api.client.get(f"{base}/bulletin-settings")).json()
    assert (settings["ref_prefix"], settings["review_required"]) == ("VOC", False)

    # Selection: a KEV CVE takes the urgent template, another one the default.
    kev = await _vulnerability(database, "CVE-2026-5001", kev=True, score=8.1)
    plain = await _vulnerability(database, "CVE-2026-5002", kev=False, score=7.5)
    match = (
        await api.client.get(
            f"{base}/bulletin-templates/match", params={"vulnerability_id": str(kev)}
        )
    ).json()
    assert (match["template_name"], match["rule_index"], match["reasons"]) == (
        "Vulnérabilité exploitée ou critique (FR)",
        0,
        ["kev: true"],
    )
    fallback = (
        await api.client.get(
            f"{base}/bulletin-templates/match", params={"vulnerability_id": str(plain)}
        )
    ).json()
    assert (fallback["template_name"], fallback["rule_index"]) == ("Bulletin générique (FR)", None)

    # Preview on the server: computed fields from the real CVE, AI fields as placeholders,
    # catalogue text and analyst values rendered as data.
    spec = copy.deepcopy(SEEDS["urgent_fr"][2])
    preview = await api.client.post(
        f"{base}/bulletin-templates/preview",
        json={
            "spec": spec,
            "vulnerability_id": str(kev),
            "fields": {"analyst_note": "Voir <script>alert(1)</script> {{ 1 }}", "nope": 1},
        },
        headers=h,
    )
    assert preview.status_code == 200, preview.text
    shown = preview.json()
    assert shown["fields"]["cves"] == ["CVE-2026-5001"]
    assert shown["fields"]["severity"] == "high"
    assert "nope" not in shown["fields"]
    assert (shown["matches"], shown["reasons"]) == (True, ["kev: true"])
    assert "[Titre : rédigé par l'IA]" in shown["markdown"]
    assert "{{ 1 }}" in shown["html"]
    assert "<script" not in shown["html"]

    # A new template: validated, versioned, activated explicitly.
    broken = copy.deepcopy(spec)
    broken["fields"][0]["generation"] = {"mode": "computed", "from": "os.environ"}
    refused = await api.client.post(
        f"{base}/bulletin-templates", json={"name": "Cassé", "spec": broken}, headers=h
    )
    assert refused.status_code == 422
    assert refused.json()["errors"][0]["path"] == "fields.0.generation"
    custom = copy.deepcopy(spec)
    custom.update(priority=500, match_rules=[{"cwe_any": ["CWE-78"]}])
    created = await api.client.post(
        f"{base}/bulletin-templates", json={"name": "Injection de commande", "spec": custom},
        headers=h,
    )  # fmt: skip
    assert created.status_code == 201, created.text
    template = created.json()
    assert (template["status"], template["active_version_no"]) == ("draft", None)
    tid = template["id"]
    custom["tlp"] = "GREEN"
    v2 = await api.client.post(
        f"{base}/bulletin-templates/{tid}/versions",
        json={"spec": custom, "comment": "TLP vert", "base_version_no": 1},
        headers=h,
    )
    assert v2.status_code == 201, v2.text
    conflict = await api.client.post(
        f"{base}/bulletin-templates/{tid}/versions",
        json={"spec": custom, "base_version_no": 1},
        headers=h,
    )
    assert conflict.status_code == 409
    # Drafts are never selected; once active, its rule wins by priority.
    assert (
        await api.client.get(
            f"{base}/bulletin-templates/match", params={"vulnerability_id": str(plain)}
        )
    ).json()["template_name"] == "Bulletin générique (FR)"
    activated = await api.client.post(
        f"{base}/bulletin-templates/{tid}/versions/2/activate", headers=h
    )
    assert activated.status_code == 200, activated.text
    assert (activated.json()["active_version_no"], activated.json()["tlp"]) == (2, "GREEN")
    now_match = (
        await api.client.get(
            f"{base}/bulletin-templates/match", params={"vulnerability_id": str(plain)}
        )
    ).json()
    assert (now_match["template_name"], now_match["reasons"]) == (
        "Injection de commande",
        ["cwe: CWE-78"],
    )
    audit = await _sql(
        database, "SELECT action FROM audit_events WHERE action LIKE 'bulletin_template.%'"
    )
    assert {r["action"] for r in audit} == {
        "bulletin_template.created",
        "bulletin_template.version_created",
        "bulletin_template.activated",
    }

    # Settings: reference prefix and double validation, optimistic locking.
    updated = await api.client.put(
        f"{base}/bulletin-settings",
        json={
            "ref_prefix": "VOC-BUL",
            "review_required": True,
            "default_template_id": tid,
            "version": settings["version"],
        },
        headers=h,
    )
    assert updated.status_code == 200, updated.text
    stale = await api.client.put(
        f"{base}/bulletin-settings",
        json={
            "ref_prefix": "X",
            "review_required": False,
            "default_template_id": None,
            "version": settings["version"],
        },
        headers=h,
    )
    assert stale.status_code == 409
    bad = await api.client.put(
        f"{base}/bulletin-settings",
        json={"ref_prefix": "voc bul", "review_required": False, "default_template_id": None,
              "version": updated.json()["version"]},
        headers=h,
    )  # fmt: skip
    assert bad.status_code == 422


async def test_templates_stay_in_their_workspace(
    make_api: ApiFactory, database: Database, redis_url: str
) -> None:
    await _seeded(database, redis_url)
    cert = await create_user(
        database.admin_dsn, "cert@cert.example.com", workspaces={"cert": "analyst"}, with_totp=True
    )
    viewer = await create_user(
        database.admin_dsn, "view@voc.example.com", workspaces={"voc": "viewer"}, with_totp=True
    )
    voc_templates = await _sql(
        database, "SELECT id FROM bulletin_templates WHERE workspace_id = $1", VOC
    )
    api: Api = await make_api("backoffice")
    hc = {"x-csrf-token": await sign_in(api, cert)}
    for template in voc_templates:
        response = await api.client.get(
            api.url(f"/workspaces/cert/bulletin-templates/{template['id']}")
        )
        assert response.status_code == 404
    names = {
        t["name"]
        for t in (await api.client.get(api.url("/workspaces/cert/bulletin-templates"))).json()
    }
    assert len(names) == 3
    await api.client.post(api.url("/auth/logout"), headers=hc)
    hv = {"x-csrf-token": await sign_in(api, viewer)}
    assert (await api.client.get(api.url("/workspaces/voc/bulletin-templates"))).status_code == 403
    denied = await api.client.post(
        api.url("/workspaces/voc/bulletin-templates"),
        json={"name": "X", "spec": SEEDS["generic_fr"][2]},
        headers=hv,
    )
    assert denied.status_code == 403
