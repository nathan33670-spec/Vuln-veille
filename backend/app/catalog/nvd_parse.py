"""Parsing of NVD CVE API 2.0 records into catalogue data.

NVD is an authoritative source, but its content is external text written by many
CNAs: types are validated, sizes are bounded and only http(s) reference URLs are
kept. Nothing here is ever interpreted as markup, template or instruction.
"""

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_DESCRIPTION = 20_000
MAX_REFERENCES = 500
MAX_URL = 2048
MAX_CPE = 5000
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}$")
SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Preference order when picking the score of record: newest CVSS, then NVD's own.
CVSS_KEYS = (
    ("cvssMetricV40", "v40"),
    ("cvssMetricV31", "v31"),
    ("cvssMetricV30", "v30"),
    ("cvssMetricV2", "v2"),
)


class NvdParseError(ValueError):
    pass


class _Loose(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class _LangValue(_Loose):
    lang: str = ""
    value: str = ""


class _CvssData(_Loose):
    version: str = ""
    vector_string: str = Field(default="", alias="vectorString")
    base_score: Decimal | None = Field(default=None, alias="baseScore", ge=0, le=10)
    base_severity: str | None = Field(default=None, alias="baseSeverity")


class _Metric(_Loose):
    source: str = ""
    type: str = ""
    cvss_data: _CvssData = Field(alias="cvssData")
    base_severity: str | None = Field(default=None, alias="baseSeverity")  # CVSS v2


class _Weakness(_Loose):
    description: list[_LangValue] = []


class _Reference(_Loose):
    url: str
    source: str = ""
    tags: list[str] = []


class _CpeMatch(_Loose):
    criteria: str
    vulnerable: bool = True


class _Node(_Loose):
    cpe_match: list[_CpeMatch] = Field(default=[], alias="cpeMatch")


class _Configuration(_Loose):
    nodes: list[_Node] = []


class _Cve(_Loose):
    id: str
    source_identifier: str | None = Field(default=None, alias="sourceIdentifier")
    published: datetime | None = None
    last_modified: datetime | None = Field(default=None, alias="lastModified")
    vuln_status: str | None = Field(default=None, alias="vulnStatus")
    cisa_exploit_add: date | None = Field(default=None, alias="cisaExploitAdd")
    cisa_action_due: date | None = Field(default=None, alias="cisaActionDue")
    cisa_required_action: str | None = Field(default=None, alias="cisaRequiredAction")
    cisa_vulnerability_name: str | None = Field(default=None, alias="cisaVulnerabilityName")
    descriptions: list[_LangValue] = []
    metrics: dict[str, list[_Metric]] = {}
    weaknesses: list[_Weakness] = []
    configurations: list[_Configuration] = []
    references: list[_Reference] = []


@dataclass(frozen=True)
class CveData:
    cve_id: str
    source_identifier: str | None
    published_at: datetime | None
    last_modified_at: datetime | None
    vuln_status: str | None
    description: str
    cvss: dict[str, list[dict[str, Any]]]
    base_score: Decimal | None
    severity: str | None
    cwes: list[str]
    references: list[dict[str, Any]]
    cpe_configurations: list[dict[str, Any]]
    cpe_criteria: list[str]
    kev: dict[str, Any] | None

    @property
    def exploit_urls(self) -> set[str]:
        return {r["url"] for r in self.references if "Exploit" in r["tags"]}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _metric_out(metric: _Metric) -> dict[str, Any]:
    severity = (metric.cvss_data.base_severity or metric.base_severity or "").upper() or None
    return {
        "source": metric.source[:200],
        "type": metric.type[:20],
        "version": metric.cvss_data.version[:8],
        "vector": metric.cvss_data.vector_string[:300],
        "score": float(metric.cvss_data.base_score)
        if metric.cvss_data.base_score is not None
        else None,
        "severity": severity if severity in SEVERITY_RANK else None,
    }


def _score_of_record(cvss: dict[str, list[dict[str, Any]]]) -> tuple[Decimal | None, str | None]:
    for _, key in CVSS_KEYS:
        metrics = [m for m in cvss.get(key, []) if m["score"] is not None]
        if metrics:
            best = next((m for m in metrics if m["type"] == "Primary"), metrics[0])
            return Decimal(str(best["score"])), best["severity"]
    return None, None


def parse_cve(item: dict[str, Any]) -> CveData:
    """One element of the API's ``vulnerabilities`` array."""
    try:
        cve = _Cve.model_validate(item.get("cve", item))
    except ValidationError as exc:
        raise NvdParseError("malformed CVE record") from exc
    if not CVE_ID.fullmatch(cve.id):
        raise NvdParseError("invalid CVE identifier")

    description = next((d.value for d in cve.descriptions if d.lang == "en"), "")
    if not description and cve.descriptions:
        description = cve.descriptions[0].value
    cvss = {
        key: [_metric_out(m) for m in cve.metrics.get(nvd_key, [])[:10]]
        for nvd_key, key in CVSS_KEYS
        if cve.metrics.get(nvd_key)
    }
    base_score, severity = _score_of_record(cvss)
    cwes = sorted(
        {
            d.value
            for w in cve.weaknesses
            for d in w.description
            if re.fullmatch(r"CWE-\d{1,6}", d.value)
        }
    )
    references = [
        {"url": r.url, "source": r.source[:200], "tags": sorted({t[:60] for t in r.tags})[:20]}
        for r in cve.references
        if r.url.startswith(("https://", "http://")) and len(r.url) <= MAX_URL
    ][:MAX_REFERENCES]
    criteria: list[str] = []
    configurations: list[dict[str, Any]] = []
    for configuration in cve.configurations:
        nodes = []
        for node in configuration.nodes:
            matches = [m for m in node.cpe_match if m.criteria.startswith("cpe:2.3:")]
            criteria.extend(m.criteria for m in matches if m.vulnerable)
            nodes.append(
                {
                    "cpe_match": [
                        {"criteria": m.criteria[:500], "vulnerable": m.vulnerable} for m in matches
                    ]
                }
            )
        configurations.append({"nodes": nodes})
        if len(criteria) > MAX_CPE:
            break
    kev = None
    if cve.cisa_exploit_add is not None:
        kev = {
            "date_added": cve.cisa_exploit_add.isoformat(),
            "due_date": cve.cisa_action_due.isoformat() if cve.cisa_action_due else None,
            "required_action": (cve.cisa_required_action or "")[:1000],
            "name": (cve.cisa_vulnerability_name or "")[:300],
        }
    return CveData(
        cve_id=cve.id,
        source_identifier=(cve.source_identifier or None) and cve.source_identifier[:200],
        published_at=_utc(cve.published),
        last_modified_at=_utc(cve.last_modified),
        vuln_status=(cve.vuln_status or None) and cve.vuln_status[:40],
        description=description[:MAX_DESCRIPTION],
        cvss=cvss,
        base_score=base_score,
        severity=severity,
        cwes=cwes,
        references=references,
        cpe_configurations=configurations,
        cpe_criteria=sorted(set(criteria))[:MAX_CPE],
        kev=kev,
    )
