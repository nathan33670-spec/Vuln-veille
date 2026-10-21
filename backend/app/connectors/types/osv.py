"""OSV, the open source vulnerability database (spec 07 §2): advisories by identifier
(CVE, GHSA, PYSEC…) and by package (purl). Free, no account."""

import re
from typing import Any

from pydantic import Field

from app.connectors.base import (
    ConnectorConfig,
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    Quotas,
    Scope,
    register,
)
from app.connectors.found import FetchError, Found, as_dict, fetch, from_iso, json_of

API = "https://api.osv.dev/v1"
VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$")
PURL = re.compile(r"^pkg:[a-z0-9.+-]+/[^\s]{1,300}$")
MAX_REFERENCES = 30


class OsvConfig(ConnectorConfig):
    max_results: int = Field(default=20, ge=1, le=100)


def _fixed_versions(affected: list[Any]) -> list[dict[str, Any]]:
    out = []
    for entry in affected[:50]:
        if not isinstance(entry, dict):
            continue
        package = as_dict(entry.get("package"))
        fixed = [
            event["fixed"]
            for r in entry.get("ranges") or []
            if isinstance(r, dict)
            for event in r.get("events") or []
            if isinstance(event, dict) and isinstance(event.get("fixed"), str)
        ]
        out.append(
            {
                "ecosystem": package.get("ecosystem"),
                "name": package.get("name"),
                "purl": package.get("purl"),
                "fixed": fixed[:20],
            }
        )
    return out


def advisory(data: Any) -> Found:
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        raise FetchError("unexpected_answer")
    references = [
        r.get("url")
        for r in data.get("references") or []
        if isinstance(r, dict) and isinstance(r.get("url"), str)
    ][:MAX_REFERENCES]
    return Found(
        source="osv",
        url=f"https://osv.dev/vulnerability/{data['id']}",
        title=f"{data['id']} {data.get('summary') or ''}".strip(),
        content=str(data.get("details") or "")[:20_000],
        published_at=from_iso(data.get("published")),
        extra={
            "osv_id": data["id"],
            "aliases": [a for a in data.get("aliases") or [] if isinstance(a, str)][:20],
            "affected": _fixed_versions(data.get("affected") or []),
            "references": references,
            "modified": data.get("modified"),
        },
    )


async def lookup(ctx: ConnectorContext, vuln_id: str) -> Found | None:
    if not VULN_ID.fullmatch(vuln_id):
        raise FetchError("invalid_identifier")
    response = await fetch(ctx, "GET", f"{API}/vulns/{vuln_id}", ok=(200, 404))
    return advisory(json_of(response)) if response.status_code == 200 else None  # noqa: PLR2004


async def by_package(ctx: ConnectorContext, purl: str) -> list[Found]:
    if not PURL.fullmatch(purl):
        raise FetchError("invalid_purl")
    response = await fetch(ctx, "POST", f"{API}/query", json_body={"package": {"purl": purl}})
    data = json_of(response)
    vulns = data.get("vulns", []) if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise FetchError("unexpected_answer")
    return [advisory(v) for v in vulns[:100]]


@register
class OsvConnector(ConnectorType):
    kind = "osv"
    family = Family.SOURCE
    label = "OSV (vulnérabilités open source)"
    scopes = frozenset({Scope.GLOBAL, Scope.WORKSPACE})
    cost_class = CostClass.FREE
    config_model = OsvConfig
    egress_domains = ("api.osv.dev",)
    content_types = ("application/json",)
    default_quotas = Quotas(requests_per_minute=60)

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        try:
            found = await lookup(ctx, "CVE-2021-44228")
        except FetchError as exc:
            return HealthResult(ok=False, message=exc.code)
        return HealthResult(ok=found is not None, message="base OSV accessible")
