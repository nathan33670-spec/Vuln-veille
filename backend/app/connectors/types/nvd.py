"""NVD (CVE API 2.0): the platform's entry vector n°1 (ADR-020, spec 07 §3).

Limits, as documented by NVD and configurable here: 5 requests per rolling
30-second window without an API key, 50 with one; at most 2,000 results per page;
date ranges of at most 120 consecutive days, both bounds required.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

from pydantic import Field

from app.connectors.base import (
    ConnectorConfig,
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    QuotaGuardProtocol,
    Scope,
    SecretSlot,
    Sleep,
    SyncJob,
    register,
)
from app.connectors.jobs import SyncError
from app.net.safe_http import EgressDeniedError, EgressError, SafeHttpClient

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RETRYABLE = frozenset({403, 429, 500, 502, 503, 504})
MAX_ATTEMPTS = 6
HEALTH_PROBE = "CVE-2021-44228"


class NvdConfig(ConnectorConfig):
    sync_interval_minutes: int = Field(
        default=120, ge=15, le=1440, description="NVD recommends at most one sync every 2 hours."
    )
    backfill_days: int = Field(
        default=90, ge=0, le=3650, description="Initial catch-up depth; it emits no events."
    )
    announce_published_within_days: int = Field(
        default=14,
        ge=1,
        le=365,
        description="A CVE never seen before is announced only if published this recently.",
    )
    page_size: int = Field(default=2000, ge=1, le=2000)
    window_days: int = Field(default=120, ge=1, le=120)
    overlap_minutes: int = Field(default=5, ge=0, le=60)
    pause_seconds_with_key: float = Field(default=0.6, ge=0, le=60)
    pause_seconds_without_key: float = Field(default=6.0, ge=0, le=60)
    backoff_seconds: float = Field(default=6.0, ge=0.1, le=300)


class NvdError(SyncError):
    pass


def nvd_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


class NvdClient:
    def __init__(
        self,
        http: SafeHttpClient,
        config: NvdConfig,
        api_key: str | None = None,
        quotas: QuotaGuardProtocol | None = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._http = http
        self._config = config
        self._headers = {"apiKey": api_key} if api_key else {}
        self._quotas = quotas
        self._sleep = sleep
        self._pause = config.pause_seconds_with_key if api_key else config.pause_seconds_without_key
        self._requests = 0

    async def _get(self, params: dict[str, str | int]) -> dict[str, Any]:
        for attempt in range(MAX_ATTEMPTS):
            if self._requests:
                await self._sleep(self._pause)
            self._requests += 1
            if self._quotas is not None:
                await self._quotas.consume()
            try:
                response = await self._http.get(NVD_CVES, params=params, headers=self._headers)
                status: int | None = response.status_code
            except EgressDeniedError:
                raise
            except EgressError:
                status = None  # timeout or network error: retried
            if status == HTTPStatus.OK:
                payload = response.json()
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("vulnerabilities"), list
                ):
                    raise NvdError("unexpected_response")
                return payload
            if status is not None and status not in RETRYABLE:
                raise NvdError(f"http_{status}")
            await self._sleep(min(300.0, self._config.backoff_seconds * 2**attempt))
        raise NvdError("retries_exhausted")

    async def window(self, start: datetime, end: datetime) -> AsyncIterator[list[dict[str, Any]]]:
        """Pages of CVEs modified in [start, end] (at most ``window_days``)."""
        index = 0
        while True:
            payload = await self._get(
                {
                    "lastModStartDate": nvd_time(start),
                    "lastModEndDate": nvd_time(end),
                    "resultsPerPage": self._config.page_size,
                    "startIndex": index,
                }
            )
            items = payload["vulnerabilities"]
            yield items
            index += len(items)
            total = payload.get("totalResults")
            if not items or not isinstance(total, int) or index >= total:
                return

    async def cve(self, cve_id: str) -> dict[str, Any] | None:
        payload = await self._get({"cveId": cve_id})
        items = payload["vulnerabilities"]
        return items[0] if items else None


@register
class NvdConnector(ConnectorType):
    kind = "nvd"
    family = Family.SOURCE
    label = "NVD (National Vulnerability Database)"
    scopes = frozenset({Scope.GLOBAL})
    cost_class = CostClass.FREE_ACCOUNT
    config_model = NvdConfig
    secret_slots = (SecretSlot("api_key", "Clé API NVD (recommandée)", required=False),)
    egress_domains = ("services.nvd.nist.gov",)
    content_types = ("application/json",)
    syncs = True

    @staticmethod
    def client(ctx: ConnectorContext, sleep: Sleep = asyncio.sleep) -> NvdClient:
        config = ctx.config
        if not isinstance(config, NvdConfig):
            raise TypeError("not an NVD configuration")
        return NvdClient(ctx.http, config, ctx.secrets.get("api_key"), ctx.quotas, sleep)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            found = await self.client(ctx).cve(HEALTH_PROBE)
        except NvdError as exc:
            return HealthResult(ok=False, message=f"nvd: {exc.code}")
        return HealthResult(ok=found is not None, message="" if found else "nvd: empty answer")

    async def sync(self, job: SyncJob) -> dict[str, int]:
        from app.catalog.nvd_sync import sync_nvd  # noqa: PLC0415 - catalogue depends on this

        config = job.ctx.config
        if not isinstance(config, NvdConfig):
            raise TypeError("not an NVD configuration")
        report = await sync_nvd(
            job.db, self.client(job.ctx, job.sleep), job.connector_id, config, job.now
        )
        return report.__dict__
