"""CISA KEV, FIRST EPSS and CVE.org synchronisations, end to end."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from pydantic import SecretStr

from app.catalog.schedule import schedule_syncs
from app.connectors.jobs import SYNC_TASK, run_sync
from app.connectors.types.cisa_kev import KEV_FEED
from app.connectors.types.cve_org import DELTA, DELTA_LOG, record_path
from app.connectors.types.epss import EPSS_API
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context
from app.core.tasks import MemoryTaskQueue
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Database
from tests.unit.test_catalog_sources import cve5
from tests.web_fakes import FakeWeb

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 21, 6, 0, tzinfo=UTC)


async def _no_sleep(_: float) -> None:
    return None


async def _sql(database: Database, query: str, *args: object) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query, *args)
    finally:
        await conn.close()


async def _connector(database: Database, kind: str, domain: str, **config: object) -> uuid.UUID:
    connector_id = uuid.uuid4()
    await _sql(
        database,
        "INSERT INTO connectors (id, family, kind, name, config, egress_domains) "
        "VALUES ($1, 'source', $2, $2, $3, ARRAY[$4])",
        connector_id,
        kind,
        json.dumps(config),
        domain,
    )
    return connector_id


async def _known(database: Database, cve_id: str, sources: list[str]) -> None:
    await _sql(
        database,
        "INSERT INTO cve_records (cve_id, description, sources, first_seen_at, synced_at) "
        "VALUES ($1, 'known', $2, now(), now())",
        cve_id,
        sources,
    )


def _settings(database: Database):  # type: ignore[no-untyped-def]
    return make_settings(database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)))


def _kev(version: str, *entries: tuple[str, str]) -> dict:  # type: ignore[type-arg]
    return {
        "catalogVersion": version,
        "vulnerabilities": [
            {
                "cveID": cve,
                "vendorProject": "V",
                "product": "P",
                "vulnerabilityName": "N",
                "dateAdded": added,
                "shortDescription": "Exploited.",
                "requiredAction": "Patch.",
                "dueDate": added,
                "knownRansomwareCampaignUse": "Unknown",
            }
            for cve, added in entries
        ],
    }


async def test_kev_bootstrap_is_silent_then_new_entries_are_announced(
    database: Database, clean_state: None
) -> None:
    await _known(database, "CVE-2021-44228", ["nvd"])
    web = FakeWeb()
    web.json(
        KEV_FEED,
        _kev("2026.10.20", ("CVE-2021-44228", "2021-12-10"), ("CVE-2019-0001", "2019-01-01")),
    )
    connector = await _connector(database, "cisa_kev", "www.cisa.gov")
    settings = _settings(database)
    http = web.client("www.cisa.gov")

    report = await run_sync(settings, connector, http=http, sleep=_no_sleep, clock=lambda: T0)
    assert report == {"entries": 2, "added": 2, "malformed": 0}
    assert await _sql(database, "SELECT id FROM outbox_events") == []
    created = await _sql(
        database, "SELECT sources, kev FROM cve_records WHERE cve_id = 'CVE-2019-0001'"
    )
    assert created[0]["sources"] == ["cisa_kev"]  # a minimal record, completed by NVD later

    unchanged = await run_sync(settings, connector, http=http, sleep=_no_sleep, clock=lambda: T0)
    assert unchanged == {"entries": 2, "added": 0, "malformed": 0}

    web.json(
        KEV_FEED,
        _kev(
            "2026.10.21",
            ("CVE-2021-44228", "2021-12-10"),
            ("CVE-2019-0001", "2019-01-01"),
            ("CVE-2026-0042", "2026-10-21"),
        ),
    )
    await run_sync(
        settings, connector, http=http, sleep=_no_sleep, clock=lambda: T0 + timedelta(hours=6)
    )
    events = await _sql(database, "SELECT type, payload FROM outbox_events")
    assert [(e["type"], json.loads(e["payload"])["cve_id"]) for e in events] == [
        ("cve.updated", "CVE-2026-0042")
    ]
    assert json.loads(events[0]["payload"])["change_types"] == ["kev_added"]


async def test_epss_refreshes_catalogue_scores_by_batches(
    database: Database, clean_state: None
) -> None:
    for n in range(5):
        await _known(database, f"CVE-2026-{n:04d}", ["nvd"])
    web = FakeWeb()

    def scores(request):  # type: ignore[no-untyped-def]
        ids = request.url.params["cve"].split(",")
        return 200, {
            "status": "OK",
            "data": [
                {"cve": cve, "epss": "0.12345", "percentile": "0.9", "date": "2026-10-20"}
                for cve in ids
            ]
            + [{"cve": "garbage"}],
        }

    web.routes[EPSS_API] = scores
    connector = await _connector(database, "epss", "api.first.org", batch_size=2)
    report = await run_sync(
        _settings(database),
        connector,
        http=web.client("api.first.org"),
        sleep=_no_sleep,
        clock=lambda: T0,
    )
    assert report == {"requested": 5, "updated": 5}
    assert len(web.requests) == 3
    rows = await _sql(database, "SELECT DISTINCT epss_score FROM cve_records")
    assert [str(r["epss_score"]) for r in rows] == ["0.12345"]


def _delta(fetch_time: str, *new: str) -> dict:  # type: ignore[type-arg]
    return {
        "fetchTime": fetch_time,
        "numberOfChanges": len(new),
        "new": [{"cveId": c, "githubLink": "https://evil.example/x.json"} for c in new],
        "updated": [],
        "error": [],
    }


async def test_cve_org_detects_early_and_catches_up_after_a_gap(
    database: Database, clean_state: None
) -> None:
    await _known(database, "CVE-2026-0007", ["nvd"])
    web = FakeWeb()
    web.json(DELTA, _delta("2026-10-21T06:00:00.000Z"))
    connector = await _connector(database, "cve_org", "raw.githubusercontent.com")
    settings = _settings(database)
    http = web.client("raw.githubusercontent.com")

    first = await run_sync(settings, connector, http=http, sleep=_no_sleep, clock=lambda: T0)
    assert first == {"entries": 0, "records": 0, "published": 0}  # starts from now

    web.json(DELTA, _delta("2026-10-21T06:07:00.000Z", "CVE-2026-100145", "CVE-2026-0007"))
    web.json(record_path("CVE-2026-100145"), cve5("CVE-2026-100145"))
    second = await run_sync(
        settings, connector, http=http, sleep=_no_sleep, clock=lambda: T0 + timedelta(minutes=7)
    )
    assert second == {"entries": 1, "records": 2, "published": 1}
    assert not any("evil.example" in str(r.url) for r in web.requests)  # paths built from ids
    assert record_path("CVE-2026-0007").split("/cves")[1] not in " ".join(web.paths())  # NVD wins
    events = await _sql(database, "SELECT type, payload FROM outbox_events")
    assert [(e["type"], json.loads(e["payload"])["source"]) for e in events] == [
        ("cve.published", "cve_org")
    ]

    # An hour later: delta.json only shows the last update; the log fills the gap.
    web.json(DELTA, _delta("2026-10-21T07:07:00.000Z"))
    web.json(
        DELTA_LOG,
        [
            _delta("2026-10-21T07:07:00.000Z"),
            _delta("2026-10-21T06:30:00.000Z", "CVE-2026-1234"),
            _delta("2026-10-21T06:00:00.000Z", "CVE-2026-9999"),  # already read before
        ],
    )
    record = cve5("CVE-2026-1234")
    record["cveMetadata"]["datePublished"] = "2026-10-21T06:20:00.000Z"
    web.json(record_path("CVE-2026-1234"), record)
    third = await run_sync(
        settings,
        connector,
        http=http,
        sleep=_no_sleep,
        clock=lambda: T0 + timedelta(hours=1, minutes=7),
    )
    assert third == {"entries": 2, "records": 1, "published": 1}
    cursor = await _sql(database, "SELECT position FROM connector_cursors WHERE stream = 'delta'")
    assert json.loads(cursor[0]["position"])["last_fetch_time"] == "2026-10-21T07:07:00+00:00"


async def test_scheduler_covers_every_synced_kind(database: Database, clean_state: None) -> None:
    ids = {
        await _connector(database, "cisa_kev", "www.cisa.gov"),
        await _connector(database, "epss", "api.first.org"),
        await _connector(database, "cve_org", "raw.githubusercontent.com"),
    }
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    tasks = MemoryTaskQueue()
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            assert await schedule_syncs(db, tasks, T0) == 3
            # CVE.org runs every 5 minutes, the others far less often.
            assert await schedule_syncs(db, tasks, T0 + timedelta(minutes=5)) == 1
    finally:
        await engine.dispose()
    assert {kwargs["connector_id"] for _, kwargs in tasks.sent} == {str(i) for i in ids}
    assert {name for name, _ in tasks.sent} == {SYNC_TASK}
