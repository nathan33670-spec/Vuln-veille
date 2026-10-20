"""NVD synchronisation end to end, against PostgreSQL and a fake NVD."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from pydantic import SecretStr

from app.catalog.nvd_sync import _lock_id, run_nvd_sync
from app.catalog.schedule import NVD_SYNC_TASK, schedule_nvd
from app.core.db import create_engine, create_sessionmaker
from app.core.rls import init_context
from app.core.tasks import MemoryTaskQueue
from tests.conftest import make_settings
from tests.integration.conftest import PASSWORDS, Database
from tests.nvd_fakes import FakeNvd, nvd_item

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


async def _no_sleep(_: float) -> None:
    return None


async def _connector(database: Database, **config: object) -> uuid.UUID:
    connector_id = uuid.uuid4()
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        await conn.execute(
            "INSERT INTO connectors (id, family, kind, name, config, egress_domains) "
            "VALUES ($1, 'source', 'nvd', 'NVD', $2, ARRAY['services.nvd.nist.gov'])",
            connector_id,
            json.dumps(config),
        )
    finally:
        await conn.close()
    return connector_id


def _settings(database: Database):  # type: ignore[no-untyped-def]
    return make_settings(database_url_worker=SecretStr(database.dsn("vv_worker", PASSWORDS.worker)))


async def _fetch(database: Database, query: str) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(database.admin_dsn)
    try:
        return await conn.fetch(query)
    finally:
        await conn.close()


async def test_backfill_then_incremental_sync(database: Database, clean_state: None) -> None:
    fake = FakeNvd(page_size_cap=2)
    fake.put(
        nvd_item(
            "CVE-2026-1001",
            published="2026-06-01T00:00:00.000",
            modified="2026-06-02T00:00:00.000",
            score=5.0,
            severity="MEDIUM",
        )
    )
    fake.put(
        nvd_item(
            "CVE-2026-1002", published="2026-09-01T00:00:00.000", modified="2026-09-02T00:00:00.000"
        )
    )
    fake.put(
        nvd_item(
            "CVE-2026-1003", published="2026-10-01T00:00:00.000", modified="2026-10-10T00:00:00.000"
        )
    )
    connector_id = await _connector(database, backfill_days=200)
    settings = _settings(database)

    report = await run_nvd_sync(
        settings, connector_id, http=fake.client(), sleep=_no_sleep, clock=lambda: T0
    )
    assert report is not None
    assert report.backfill_records == 3
    assert report.windows == 3  # two backfill windows (120 + 80 days) and one incremental
    windows = [(q["lastModStartDate"], q["lastModEndDate"]) for q in fake.queries]
    assert all(
        (datetime.fromisoformat(e) - datetime.fromisoformat(s)).days <= 120 for s, e in windows
    )
    assert await _fetch(database, "SELECT * FROM outbox_events") == []  # backfill is silent
    records = await _fetch(database, "SELECT cve_id, from_backfill FROM cve_records ORDER BY 1")
    assert [(r["cve_id"], r["from_backfill"]) for r in records] == [
        ("CVE-2026-1001", True),
        ("CVE-2026-1002", True),
        ("CVE-2026-1003", True),
    ]

    # Two hours later: an enrichment, a brand-new CVE and an old CVE edited today.
    t1 = T0 + timedelta(hours=2)
    fake.put(
        nvd_item(
            "CVE-2026-1001",
            published="2026-06-01T00:00:00.000",
            modified="2026-10-22T13:00:00.000",
            score=9.8,
            severity="CRITICAL",
            kev=True,
            exploit_urls=("https://github.com/x/poc",),
        )
    )
    fake.put(
        nvd_item(
            "CVE-2026-2000", published="2026-10-22T12:30:00.000", modified="2026-10-22T12:30:00.000"
        )
    )
    fake.put(
        nvd_item(
            "CVE-2015-0001", published="2015-01-01T00:00:00.000", modified="2026-10-22T13:30:00.000"
        )
    )
    fake.queries.clear()
    second = await run_nvd_sync(
        settings, connector_id, http=fake.client(), sleep=_no_sleep, clock=lambda: t1
    )
    assert second is not None
    start = datetime.fromisoformat(fake.queries[0]["lastModStartDate"])
    assert start == T0 - timedelta(minutes=5)  # resumes from the cursor, with the overlap

    events = await _fetch(database, "SELECT type, payload FROM outbox_events ORDER BY id")
    summary = {
        (e["type"], json.loads(e["payload"])["cve_id"]): json.loads(e["payload"]) for e in events
    }
    assert set(summary) == {("cve.published", "CVE-2026-2000"), ("cve.updated", "CVE-2026-1001")}
    assert summary[("cve.updated", "CVE-2026-1001")]["change_types"] == [
        "severity_raised",
        "kev_added",
        "exploit_reference_added",
    ]
    old = await _fetch(
        database, "SELECT change_types FROM cve_changes WHERE cve_id = 'CVE-2015-0001'"
    )
    assert [r["change_types"] for r in old] == [["published"]]  # catalogued, not announced

    third = await run_nvd_sync(
        settings,
        connector_id,
        http=fake.client(),
        sleep=_no_sleep,
        clock=lambda: t1 + timedelta(minutes=1),
    )
    assert third is not None
    assert len(await _fetch(database, "SELECT id FROM outbox_events")) == 2  # replay: nothing new

    health = await _fetch(database, "SELECT last_success_at, consecutive_failures FROM connectors")
    assert health[0]["consecutive_failures"] == 0
    assert health[0]["last_success_at"] is not None


async def test_failures_keep_the_cursor_and_mark_the_connector(
    database: Database, clean_state: None
) -> None:
    fake = FakeNvd()
    connector_id = await _connector(database, backfill_days=0, backoff_seconds=0.1)
    settings = _settings(database)
    assert await run_nvd_sync(
        settings, connector_id, http=fake.client(), sleep=_no_sleep, clock=lambda: T0
    )
    fake.fail_with = 503
    failed = await run_nvd_sync(
        settings,
        connector_id,
        http=fake.client(),
        sleep=_no_sleep,
        clock=lambda: T0 + timedelta(hours=2),
    )
    assert failed is None
    row = (await _fetch(database, "SELECT last_error, consecutive_failures FROM connectors"))[0]
    assert (row["last_error"], row["consecutive_failures"]) == ("sync: retries_exhausted", 1)
    cursor = await _fetch(database, "SELECT position FROM connector_cursors WHERE stream = 'cves'")
    assert json.loads(cursor[0]["position"])["last_end"] == T0.isoformat()


async def test_one_sync_at_a_time(database: Database, clean_state: None) -> None:
    connector_id = await _connector(database, backfill_days=0)
    holder = await asyncpg.connect(database.admin_dsn)
    try:
        await holder.execute("SELECT pg_advisory_lock($1)", _lock_id(connector_id))
        result = await run_nvd_sync(
            _settings(database),
            connector_id,
            http=FakeNvd().client(),
            sleep=_no_sleep,
            clock=lambda: T0,
        )
        assert result is None
    finally:
        await holder.close()


async def test_scheduler_queues_each_sync_once_per_interval(
    database: Database, clean_state: None
) -> None:
    connector_id = await _connector(database, sync_interval_minutes=120)
    engine = create_engine(database.dsn("vv_worker", PASSWORDS.worker))
    tasks = MemoryTaskQueue()
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            assert await schedule_nvd(db, tasks, T0) == 1
            assert await schedule_nvd(db, tasks, T0 + timedelta(minutes=119)) == 0
            assert await schedule_nvd(db, tasks, T0 + timedelta(minutes=120)) == 1
    finally:
        await engine.dispose()
    assert tasks.sent == [(NVD_SYNC_TASK, {"connector_id": str(connector_id)})] * 2
