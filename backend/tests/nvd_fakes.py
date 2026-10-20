"""Fake NVD records and server for tests (no network)."""

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs

import httpx

from app.net.safe_http import EgressPolicy, SafeHttpClient


def nvd_item(
    cve_id: str,
    *,
    published: str = "2026-10-20T10:00:00.000",
    modified: str = "2026-10-21T10:00:00.000",
    score: float | None = 7.5,
    severity: str = "HIGH",
    cpes: tuple[str, ...] = ("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",),
    exploit_urls: tuple[str, ...] = (),
    kev: bool = False,
    status: str = "Analyzed",
) -> dict[str, Any]:
    cve: dict[str, Any] = {
        "id": cve_id,
        "sourceIdentifier": "security@apache.org",
        "published": published,
        "lastModified": modified,
        "vulnStatus": status,
        "descriptions": [
            {"lang": "es", "value": "Descripción"},
            {"lang": "en", "value": f"Remote code execution in {cve_id}."},
        ],
        "metrics": {},
        "weaknesses": [
            {
                "source": "nvd",
                "type": "Primary",
                "description": [
                    {"lang": "en", "value": "CWE-917"},
                    {"lang": "en", "value": "NVD-CWE-Other"},
                ],
            }
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": c, "matchCriteriaId": "x"}
                            for c in cpes
                        ],
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://logging.apache.org/security.html",
                "source": "apache",
                "tags": ["Vendor Advisory"],
            },
            {"url": "javascript:alert(1)", "source": "evil", "tags": ["Exploit"]},
            *(
                {"url": u, "source": "x", "tags": ["Exploit", "Third Party Advisory"]}
                for u in exploit_urls
            ),
        ],
    }
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [
            {
                "source": "cna@example.org",
                "type": "Secondary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N",
                    "baseScore": 5.0,
                    "baseSeverity": "MEDIUM",
                },
            },
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L",
                    "baseScore": score,
                    "baseSeverity": severity,
                },
            },
        ]
    if kev:
        cve.update(
            cisaExploitAdd="2026-10-21",
            cisaActionDue="2026-11-11",
            cisaRequiredAction="Apply updates.",
            cisaVulnerabilityName="Log4Shell",
        )
    return {"cve": cve}


def _when(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


class FakeNvd:
    """Answers ``lastModStartDate``/``lastModEndDate`` queries from ``records``."""

    def __init__(self, page_size_cap: int = 2) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.queries: list[dict[str, str]] = []
        self.page_size_cap = page_size_cap
        self.fail_with: int | None = None

    def put(self, item: dict[str, Any]) -> None:
        self.records[item["cve"]["id"]] = item

    def handler(self, request: httpx.Request) -> httpx.Response:
        query = {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}
        self.queries.append(query)
        if self.fail_with is not None:
            return httpx.Response(self.fail_with, stream=httpx.ByteStream(b""))
        if "cveId" in query:
            items = [self.records[query["cveId"]]] if query["cveId"] in self.records else []
            total = len(items)
        else:
            start, end = _when(query["lastModStartDate"]), _when(query["lastModEndDate"])
            assert (end - start).days <= 120
            matching = sorted(
                (
                    i
                    for i in self.records.values()
                    if start <= _when(i["cve"]["lastModified"] + "+00:00") <= end
                ),
                key=lambda i: i["cve"]["id"],
            )
            size = min(int(query["resultsPerPage"]), self.page_size_cap)
            index = int(query["startIndex"])
            items, total = matching[index : index + size], len(matching)
        body = httpx.Response(
            200,
            json={
                "resultsPerPage": len(items),
                "startIndex": 0,
                "totalResults": total,
                "vulnerabilities": items,
            },
        )
        return httpx.Response(
            200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(body.content)
        )

    def client(self) -> SafeHttpClient:
        async def resolve(host: str, port: int) -> list[str]:
            return ["93.184.215.14"]

        return SafeHttpClient(
            EgressPolicy(
                allowed_domains=("services.nvd.nist.gov",),
                allowed_content_types=("application/json",),
            ),
            proxy=None,
            resolver=resolve,
            transport=httpx.MockTransport(self.handler),
        )
