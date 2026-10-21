"""FIRST EPSS: daily probability of exploitation of the catalogue's CVEs.

Only CVEs already in the catalogue are refreshed, by batches of identifiers on the
public API, oldest scores first; no event is emitted.
"""

from datetime import UTC, timedelta

from pydantic import Field, ValidationError
from sqlalchemy import or_, select

from app.catalog.enrich import EpssScore, apply_epss
from app.catalog.models import CveRecord
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
from app.connectors.jobs import SyncError

EPSS_API = "https://api.first.org/data/v1/epss"
PROBE = "CVE-2021-44228"


class EpssConfig(ConnectorConfig):
    sync_interval_minutes: int = Field(default=1440, ge=360, le=10080)
    batch_size: int = Field(default=100, ge=1, le=100)
    max_cves_per_run: int = Field(default=20000, ge=100, le=200000)
    pause_seconds: float = Field(default=1.0, ge=0, le=60)


async def _scores(ctx: ConnectorContext, cve_ids: list[str]) -> list[EpssScore]:
    if ctx.quotas is not None:
        await ctx.quotas.consume()
    response = await ctx.http.get(EPSS_API, params={"cve": ",".join(cve_ids)})
    if response.status_code != 200:  # noqa: PLR2004
        raise SyncError(f"http_{response.status_code}")
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise SyncError("unexpected_response")
    scores = []
    for item in payload["data"]:
        try:
            scores.append(EpssScore.model_validate(item))
        except ValidationError:
            continue
    return scores


@register
class EpssConnector(ConnectorType):
    kind = "epss"
    family = Family.SOURCE
    label = "FIRST EPSS (probabilité d'exploitation)"
    scopes = frozenset({Scope.GLOBAL})
    cost_class = CostClass.FREE
    config_model = EpssConfig
    egress_domains = ("api.first.org",)
    content_types = ("application/json",)
    syncs = True

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            scores = await _scores(ctx, [PROBE])
        except SyncError as exc:
            return HealthResult(ok=False, message=f"epss: {exc.code}")
        return HealthResult(ok=bool(scores), message="")

    async def sync(self, job: SyncJob) -> dict[str, int]:
        config = job.ctx.config
        if not isinstance(config, EpssConfig):
            raise TypeError("not an EPSS configuration")
        # Scores are published once a day: refresh what is older than a day.
        today = job.now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        stale = today - timedelta(days=1)
        rows = await job.db.execute(
            select(CveRecord.cve_id)
            .where(or_(CveRecord.epss_date.is_(None), CveRecord.epss_date < stale))
            .order_by(CveRecord.epss_date.asc().nulls_first(), CveRecord.cve_id)
            .limit(config.max_cves_per_run)
        )
        cve_ids = list(rows.scalars())
        updated = 0
        for start in range(0, len(cve_ids), config.batch_size):
            if start:
                await job.sleep(config.pause_seconds)
            updated += await apply_epss(
                job.db, await _scores(job.ctx, cve_ids[start : start + config.batch_size])
            )
            await job.db.commit()
        return {"requested": len(cve_ids), "updated": updated}
