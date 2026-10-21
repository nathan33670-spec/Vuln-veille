"""Parsing of CVE JSON 5 records (cvelistV5, CVE.org) into catalogue data.

These records come straight from the CNAs, before NVD analysis: same defensive
rules as the NVD parser (bounded sizes, http(s) references, identifiers checked).
CVSS from the CNA and from ADP containers (e.g. CISA Vulnrichment) is kept with its
provider; reference tags are mapped to NVD's spelling so exploit detection works
across both sources.
"""

import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from app.catalog.nvd_parse import (
    CVE_ID,
    MAX_CPE,
    MAX_DESCRIPTION,
    MAX_REFERENCES,
    MAX_URL,
    SEVERITY_RANK,
    CveData,
    NvdParseError,
)

CVSS5 = (("cvssV4_0", "v40"), ("cvssV3_1", "v31"), ("cvssV3_0", "v30"), ("cvssV2_0", "v2"))
MAX_CPE_LENGTH = 500
TAGS = {
    "exploit": "Exploit",
    "vendor-advisory": "Vendor Advisory",
    "patch": "Patch",
    "third-party-advisory": "Third Party Advisory",
    "mitigation": "Mitigation",
    "release-notes": "Release Notes",
    "technical-description": "Technical Description",
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str(value: Any, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _metrics(container: dict[str, Any], provider: str) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, list[dict[str, Any]]] = {}
    for metric in _list(container.get("metrics"))[:20]:
        for key, version in CVSS5:
            data = _dict(_dict(metric).get(key))
            if not data:
                continue
            try:
                score = Decimal(str(data.get("baseScore")))
            except InvalidOperation:
                continue
            if not Decimal(0) <= score <= Decimal(10):
                continue
            severity = _str(data.get("baseSeverity"), 10).upper()
            found.setdefault(version, []).append(
                {
                    "source": provider[:200],
                    "type": "Secondary",
                    "version": _str(data.get("version"), 8),
                    "vector": _str(data.get("vectorString"), 300),
                    "score": float(score),
                    "severity": severity if severity in SEVERITY_RANK else None,
                }
            )
    return found


def parse_cve5(record: dict[str, Any]) -> CveData:
    metadata = _dict(record.get("cveMetadata"))
    cve_id = metadata.get("cveId")
    if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id):
        raise NvdParseError("invalid CVE identifier")
    containers = _dict(record.get("containers"))
    cna = _dict(containers.get("cna"))
    rejected = metadata.get("state") == "REJECTED"
    descriptions = _list(cna.get("descriptions")) or _list(cna.get("rejectedReasons"))
    description = next(
        (
            _str(d.get("value"), MAX_DESCRIPTION)
            for d in descriptions
            if isinstance(d, dict) and str(d.get("lang", "")).startswith("en")
        ),
        "",
    )

    cvss: dict[str, list[dict[str, Any]]] = {}
    providers = [(cna, _str(metadata.get("assignerShortName"), 100) or "cna")]
    providers += [
        (_dict(adp), _str(_dict(_dict(adp).get("providerMetadata")).get("shortName"), 100) or "adp")
        for adp in _list(containers.get("adp"))[:10]
    ]
    for container, provider in providers:
        for version, metrics in _metrics(container, provider).items():
            cvss.setdefault(version, []).extend(metrics)
    base_score, severity = None, None
    for _, version in CVSS5:
        if cvss.get(version):
            base_score = Decimal(str(cvss[version][0]["score"]))
            severity = cvss[version][0]["severity"]
            break

    cwes = sorted(
        {
            d["cweId"]
            for problem in _list(cna.get("problemTypes"))
            for d in _list(_dict(problem).get("descriptions"))
            if isinstance(d, dict)
            and isinstance(d.get("cweId"), str)
            and re.fullmatch(r"CWE-\d{1,6}", d["cweId"])
        }
    )
    references: list[dict[str, Any]] = []
    for container, _ in providers:
        for ref in _list(container.get("references")):
            url = _dict(ref).get("url")
            if not isinstance(url, str) or not url.startswith(("https://", "http://")):
                continue
            if len(url) > MAX_URL or any(r["url"] == url for r in references):
                continue
            tags = sorted(
                {TAGS.get(t, t)[:60] for t in _list(ref.get("tags")) if isinstance(t, str)}
            )
            references.append({"url": url, "source": "cve_org", "tags": tags[:20]})
    criteria = sorted(
        {
            cpe
            for affected in _list(cna.get("affected"))
            for cpe in _list(_dict(affected).get("cpes"))
            if isinstance(cpe, str) and cpe.startswith("cpe:2.3:") and len(cpe) <= MAX_CPE_LENGTH
        }
    )[:MAX_CPE]
    return CveData(
        cve_id=cve_id,
        source_identifier=_str(metadata.get("assignerShortName"), 200) or None,
        published_at=_when(metadata.get("datePublished")),
        last_modified_at=_when(metadata.get("dateUpdated")),
        vuln_status="Rejected" if rejected else "Published",
        description=description,
        cvss=cvss,
        base_score=base_score,
        severity=severity,
        cwes=cwes,
        references=references[:MAX_REFERENCES],
        cpe_configurations=[],
        cpe_criteria=criteria,
        kev=None,
    )
