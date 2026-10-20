"""NVD parsing, change detection and API client behaviour."""

from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest

from app.catalog.models import CveRecord
from app.catalog.nvd_parse import NvdParseError, parse_cve
from app.catalog.store import detect
from app.connectors.types.nvd import NvdClient, NvdConfig, NvdError
from tests.nvd_fakes import FakeNvd, nvd_item


def _record(item: dict) -> CveRecord:  # type: ignore[type-arg]
    data = parse_cve(item)
    return CveRecord(
        cve_id=data.cve_id,
        cvss=data.cvss,
        base_score=data.base_score,
        severity=data.severity,
        cpe_criteria=data.cpe_criteria,
        references=data.references,
        kev=data.kev,
        vuln_status=data.vuln_status,
    )


def test_parse_keeps_what_matters_and_bounds_the_rest() -> None:
    data = parse_cve(nvd_item("CVE-2021-44228", kev=True, exploit_urls=("https://x.example/poc",)))
    assert data.description == "Remote code execution in CVE-2021-44228."
    assert data.base_score == Decimal("7.5")  # NVD's own (Primary) score is the one of record
    assert data.severity == "HIGH"
    assert data.cwes == ["CWE-917"]
    assert data.published_at == datetime(2026, 10, 20, 10, tzinfo=UTC)
    assert data.cpe_criteria == ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"]
    assert data.kev is not None
    assert data.kev["date_added"] == "2026-10-21"
    assert data.exploit_urls == {"https://x.example/poc"}
    assert all(r["url"].startswith("https://") for r in data.references)  # javascript: dropped


def test_parse_prefers_cvss4() -> None:
    item = nvd_item("CVE-2026-0001")
    item["cve"]["metrics"]["cvssMetricV40"] = [
        {
            "source": "cna",
            "type": "Secondary",
            "cvssData": {
                "version": "4.0",
                "vectorString": "CVSS:4.0/AV:N",
                "baseScore": 9.3,
                "baseSeverity": "CRITICAL",
            },
        }
    ]
    data = parse_cve(item)
    assert (data.base_score, data.severity) == (Decimal("9.3"), "CRITICAL")


@pytest.mark.parametrize("cve_id", ["CVE-21-1", "cve-2026-0001", "CVE-2026-0001; DROP", ""])
def test_parse_refuses_invalid_identifiers(cve_id: str) -> None:
    with pytest.raises(NvdParseError):
        parse_cve(nvd_item(cve_id))


def test_parse_refuses_malformed_records() -> None:
    with pytest.raises(NvdParseError):
        parse_cve(
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 42}}]},
                }
            }
        )


def test_detection() -> None:
    base = nvd_item("CVE-2026-0002", score=None)
    assert detect(None, parse_cve(base)).change_types == ["published"]
    old = _record(base)
    assert detect(old, parse_cve(base)).change_types == []  # replay: nothing new

    scored = _record(nvd_item("CVE-2026-0002", score=5.0, severity="MEDIUM"))
    assert detect(
        old, parse_cve(nvd_item("CVE-2026-0002", score=5.0, severity="MEDIUM"))
    ).change_types == ["cvss_added"]

    raised = detect(scored, parse_cve(nvd_item("CVE-2026-0002", score=9.8, severity="CRITICAL")))
    assert raised.change_types == ["severity_raised"]
    assert raised.diff["cvss"]["before"]["severity"] == "MEDIUM"

    richer = parse_cve(
        nvd_item(
            "CVE-2026-0002",
            score=5.0,
            severity="MEDIUM",
            kev=True,
            cpes=(
                "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:vmware:horizon:*:*:*:*:*:*:*:*",
            ),
            exploit_urls=("https://github.com/x/poc",),
        )
    )
    assert detect(scored, richer).change_types == [
        "cpe_added",
        "kev_added",
        "exploit_reference_added",
    ]

    rejected = parse_cve(nvd_item("CVE-2026-0002", score=5.0, severity="MEDIUM", status="Rejected"))
    assert detect(scored, rejected).change_types == ["rejected"]

    lowered = parse_cve(nvd_item("CVE-2026-0002", score=3.0, severity="LOW"))
    assert detect(scored, lowered).change_types == []


async def test_client_paginates_pauses_and_sends_the_key() -> None:
    fake = FakeNvd(page_size_cap=2)
    for n in range(5):
        fake.put(nvd_item(f"CVE-2026-{n:04d}"))
    pauses: list[float] = []

    async def sleep(seconds: float) -> None:
        pauses.append(seconds)

    client = NvdClient(fake.client(), NvdConfig(), api_key="k-123", sleep=sleep)
    pages = [
        page
        async for page in client.window(
            datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 30, tzinfo=UTC)
        )
    ]
    assert [len(p) for p in pages] == [2, 2, 1]
    assert pauses == [0.6, 0.6]  # with a key: 50 requests per 30 s
    assert fake.queries[0]["lastModStartDate"] == "2026-10-01T00:00:00.000+00:00"
    assert [q["startIndex"] for q in fake.queries] == ["0", "2", "4"]


async def test_client_backs_off_then_gives_up() -> None:
    fake = FakeNvd()
    fake.fail_with = 503
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    client = NvdClient(fake.client(), NvdConfig(backoff_seconds=1), sleep=sleep)
    with pytest.raises(NvdError) as exc:
        await client.cve("CVE-2021-44228")
    assert exc.value.code == "retries_exhausted"
    backoffs = [w for w in waits if w != NvdConfig().pause_seconds_without_key]
    assert backoffs == [1, 2, 4, 8, 16, 32]

    fake.fail_with = 404
    with pytest.raises(NvdError) as missing:
        await NvdClient(fake.client(), NvdConfig(), sleep=sleep).cve("CVE-2021-44228")
    assert missing.value.code == "http_404"


async def test_api_key_header_only_when_configured() -> None:
    seen: list[httpx.Headers] = []
    fake = FakeNvd()
    original = fake.handler

    def spy(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return original(request)

    fake.handler = spy  # type: ignore[method-assign]
    await NvdClient(fake.client(), NvdConfig()).cve("CVE-2021-44228")
    assert "apikey" not in seen[-1]
