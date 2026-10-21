"""CVE.org (cvelistV5): early detection of CVEs published by the CNAs (Q24).

New records often reach CVE.org before NVD. Every few minutes the connector reads
the repository's ``delta.json`` (the last update, about every 7 minutes); after a
gap it catches up with ``deltaLog.json`` (30 days of updates, about 30 MB). Each
listed record is read from its path in the repository, built from the identifier
(never from a URL found in the data).

A record already known from NVD is left alone (NVD is authoritative); otherwise it
goes through the same change detection, with ``cve_org`` as the source.
"""

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import Field

from app.catalog.cve5_parse import parse_cve5
from app.catalog.models import CveRecord
from app.catalog.nvd_parse import CVE_ID, NvdParseError
from app.catalog.store import upsert_cve
from app.connectors.base import (
    ConnectorConfig,
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    Scope,
    SyncJob,
    register,
)
from app.connectors.cursors import get_cursor, save_cursor
from app.connectors.jobs import SyncError

REPOSITORY = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
DELTA = f"{REPOSITORY}/delta.json"
DELTA_LOG = f"{REPOSITORY}/deltaLog.json"
_ID = re.compile(r"^CVE-(\d{4})-(\d{4,19})$")


class CveOrgConfig(ConnectorConfig):
    sync_interval_minutes: int = Field(default=5, ge=5, le=1440)
    gap_minutes: int = Field(
        default=15,
        ge=5,
        le=1440,
        description="Beyond this delay since the last update read, catch up with the log.",
    )
    announce_published_within_days: int = Field(default=14, ge=1, le=365)
    max_records_per_run: int = Field(default=500, ge=1, le=10000)
    pause_seconds: float = Field(default=0.2, ge=0, le=60)


def record_path(cve_id: str) -> str:
    """cves/2026/100xxx/CVE-2026-100145.json (the repository's layout)."""
    match = _ID.fullmatch(cve_id)
    if match is None:
        raise SyncError("invalid_identifier")
    year, number = match.groups()
    return f"{REPOSITORY}/{year}/{int(number) // 1000}xxx/{cve_id}.json"


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


async def _json(ctx: ConnectorContext, url: str) -> Any:
    if ctx.quotas is not None:
        await ctx.quotas.consume()
    response = await ctx.http.get(url)
    if response.status_code == 404:  # noqa: PLR2004 - a record not published yet
        return None
    if response.status_code != 200:  # noqa: PLR2004
        raise SyncError(f"http_{response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise SyncError("invalid_json") from exc


def _changed_ids(delta: dict[str, Any]) -> list[str]:
    ids = []
    for key in ("new", "updated"):
        for item in delta.get(key) or []:
            cve_id = item.get("cveId") if isinstance(item, dict) else None
            if isinstance(cve_id, str) and CVE_ID.fullmatch(cve_id):
                ids.append(cve_id)
    return ids


@register
class CveOrgConnector(ConnectorType):
    kind = "cve_org"
    family = Family.SOURCE
    label = "CVE.org (cvelistV5, détection précoce)"
    scopes = frozenset({Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = CveOrgConfig
    egress_domains = ("raw.githubusercontent.com",)
    content_types = ("application/json", "text/plain")  # raw GitHub serves text/plain
    max_response_bytes = 64 * 1024 * 1024
    syncs = True

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            delta = await _json(ctx, DELTA)
        except SyncError as exc:
            return HealthResult(ok=False, message=f"cve.org: {exc.code}")
        ok = isinstance(delta, dict) and _when(delta.get("fetchTime")) is not None
        return HealthResult(ok=ok, message="" if ok else "cve.org: unexpected answer")

    async def sync(self, job: SyncJob) -> dict[str, int]:
        config = job.ctx.config
        if not isinstance(config, CveOrgConfig):
            raise TypeError("not a CVE.org configuration")
        cursor = await get_cursor(job.db, job.connector_id, "delta", job.now)
        last = _when(cursor.position.get("last_fetch_time"))
        delta = await _json(job.ctx, DELTA)
        latest = _when(delta.get("fetchTime")) if isinstance(delta, dict) else None
        if latest is None:
            raise SyncError("unexpected_delta")
        if last is None:  # first run: start from now, announce nothing from the past
            save_cursor(cursor, job.now, last_fetch_time=latest.isoformat())
            await job.db.commit()
            return {"entries": 0, "records": 0, "published": 0}
        if latest <= last:
            return {"entries": 0, "records": 0, "published": 0}

        entries: list[dict[str, Any]] = [delta]
        if latest - last > timedelta(minutes=config.gap_minutes):
            log = await _json(job.ctx, DELTA_LOG)
            entries = [e for e in log if isinstance(e, dict)] if isinstance(log, list) else []
        pending = sorted(
            ((t, e) for e in entries if (t := _when(e.get("fetchTime"))) and t > last),
            key=lambda pair: pair[0],
        )
        report = {"entries": 0, "records": 0, "published": 0}
        within = timedelta(days=config.announce_published_within_days)
        for fetch_time, entry in pending:
            ids = list(dict.fromkeys(_changed_ids(entry)))
            if report["records"] + len(ids) > config.max_records_per_run and report["entries"]:
                break  # the cursor stops before this update; the next run resumes here
            for cve_id in ids:
                published = await self._apply(job, cve_id, within)
                report["records"] += 1
                report["published"] += published
                await job.sleep(config.pause_seconds)
            save_cursor(cursor, job.now, last_fetch_time=fetch_time.isoformat())
            await job.db.commit()
            report["entries"] += 1
        return report

    async def _apply(self, job: SyncJob, cve_id: str, within: timedelta) -> int:
        known = await job.db.get(CveRecord, cve_id)
        if known is not None and "nvd" in known.sources:
            return 0  # NVD's analysed record wins; CVE.org only detects early
        raw = await _json(job.ctx, record_path(cve_id))
        if not isinstance(raw, dict):
            return 0
        try:
            data = parse_cve5(raw)
        except NvdParseError:
            return 0
        detected = await upsert_cve(
            job.db, data, source="cve_org", now=job.now, backfill=False, announce_within=within
        )
        return int(detected.change_types == ["published"])
