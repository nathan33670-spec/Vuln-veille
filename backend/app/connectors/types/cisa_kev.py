"""CISA Known Exploited Vulnerabilities: the "actively exploited" status (spec 07 §2).

The official JSON feed, read whole (about 1.5 MB). The first import, and any import
of an unchanged catalogue version, announces nothing.
"""

from datetime import timedelta

from pydantic import Field

from app.catalog.enrich import apply_kev, parse_kev_feed
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
from app.net.safe_http import SafeResponse

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevConfig(ConnectorConfig):
    sync_interval_minutes: int = Field(default=360, ge=60, le=1440)
    announce_added_within_days: int = Field(default=14, ge=1, le=365)


async def _feed(ctx: ConnectorContext) -> SafeResponse:
    if ctx.quotas is not None:
        await ctx.quotas.consume()
    response = await ctx.http.get(KEV_FEED)
    if response.status_code != 200:  # noqa: PLR2004
        raise SyncError(f"http_{response.status_code}")
    return response


@register
class CisaKevConnector(ConnectorType):
    kind = "cisa_kev"
    family = Family.SOURCE
    label = "CISA KEV (vulnérabilités exploitées)"
    scopes = frozenset({Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = KevConfig
    egress_domains = ("www.cisa.gov",)
    content_types = ("application/json",)
    syncs = True

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            version, entries, _ = parse_kev_feed((await _feed(ctx)).json())
        except (SyncError, ValueError):
            return HealthResult(ok=False, message="kev: unexpected answer")
        return HealthResult(ok=bool(entries), message=f"catalogue {version}")

    async def sync(self, job: SyncJob) -> dict[str, int]:
        config = job.ctx.config
        if not isinstance(config, KevConfig):
            raise TypeError("not a KEV configuration")
        try:
            version, entries, malformed = parse_kev_feed((await _feed(job.ctx)).json())
        except ValueError as exc:
            raise SyncError("unexpected_feed") from exc
        cursor = await get_cursor(job.db, job.connector_id, "kev", job.now)
        if version and cursor.position.get("catalog_version") == version:
            return {"entries": len(entries), "added": 0, "malformed": malformed}
        bootstrapped = bool(cursor.position.get("bootstrapped"))
        added = await apply_kev(
            job.db,
            entries,
            now=job.now,
            announce=bootstrapped,
            announce_within=timedelta(days=config.announce_added_within_days),
        )
        save_cursor(cursor, job.now, catalog_version=version, bootstrapped=True)
        await job.db.commit()
        return {"entries": len(entries), "added": added, "malformed": malformed}
