"""Parsing of CVE JSON 5 records, the KEV feed and EPSS scores."""

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.catalog.cve5_parse import parse_cve5
from app.catalog.enrich import EpssScore, parse_kev_feed
from app.catalog.nvd_parse import NvdParseError
from app.connectors.jobs import SyncError
from app.connectors.types.cve_org import record_path


def cve5(cve_id: str = "CVE-2026-100145", **cna: object) -> dict:  # type: ignore[type-arg]
    container = {
        "descriptions": [{"lang": "en", "value": "SQL injection in Acme Portal."}],
        "affected": [
            {
                "vendor": "Acme",
                "product": "Portal",
                "cpes": ["cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*", "not-a-cpe"],
            }
        ],
        "problemTypes": [{"descriptions": [{"type": "CWE", "cweId": "CWE-89"}]}],
        "metrics": [
            {
                "cvssV3_1": {
                    "version": "3.1",
                    "baseScore": 8.8,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:N",
                }
            }
        ],
        "references": [
            {"url": "https://acme.example/advisory", "tags": ["vendor-advisory"]},
            {"url": "https://github.com/x/poc", "tags": ["exploit"]},
            {"url": "file:///etc/passwd"},
        ],
        **cna,
    }
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "assignerShortName": "acme",
            "datePublished": "2026-10-21T05:00:00.000Z",
            "dateUpdated": "2026-10-21T06:00:00.000Z",
        },
        "containers": {
            "cna": container,
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [
                        {
                            "cvssV4_0": {
                                "version": "4.0",
                                "baseScore": 9.3,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ],
                }
            ],
        },
    }


def test_cve5_record() -> None:
    data = parse_cve5(cve5())
    assert data.cve_id == "CVE-2026-100145"
    assert data.published_at == datetime(2026, 10, 21, 5, tzinfo=UTC)
    assert data.description == "SQL injection in Acme Portal."
    assert (data.base_score, data.severity) == (Decimal("9.3"), "CRITICAL")  # CVSS 4.0 first
    assert data.cvss["v40"][0]["source"] == "CISA-ADP"
    assert data.cwes == ["CWE-89"]
    assert data.cpe_criteria == ["cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*"]
    assert data.exploit_urls == {"https://github.com/x/poc"}  # tag mapped to NVD's spelling
    assert [r["url"] for r in data.references] == [
        "https://acme.example/advisory",
        "https://github.com/x/poc",
    ]


def test_cve5_rejected_and_hostile_values() -> None:
    record = cve5(metrics=[{"cvssV3_1": {"baseScore": "99"}}, {"cvssV3_1": {"baseScore": "x"}}])
    record["cveMetadata"]["state"] = "REJECTED"
    data = parse_cve5(record)
    assert data.vuln_status == "Rejected"
    assert data.cvss.get("v31") is None
    with pytest.raises(NvdParseError):
        parse_cve5(cve5("CVE-2026-1/../../x"))


@pytest.mark.parametrize(
    ("cve_id", "folder"),
    [
        ("CVE-2026-100145", "100xxx"),
        ("CVE-2026-1234", "1xxx"),
        ("CVE-2026-0123", "0xxx"),
        ("CVE-2021-44228", "44xxx"),
    ],
)
def test_record_paths(cve_id: str, folder: str) -> None:
    assert record_path(cve_id).endswith(f"/{cve_id[4:8]}/{folder}/{cve_id}.json")


def test_record_paths_refuse_anything_else() -> None:
    with pytest.raises(SyncError):
        record_path("CVE-2026-1234/../../../secrets")


def test_kev_feed_skips_malformed_entries() -> None:
    version, entries, malformed = parse_kev_feed(
        {
            "catalogVersion": "2026.10.21",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "requiredAction": "Patch.",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "not-a-cve", "dateAdded": "2021-12-10"},
                {"cveID": "CVE-2026-0001"},
            ],
        }
    )
    assert version == "2026.10.21"
    assert malformed == 2
    assert entries[0].as_kev()["ransomware"] is True
    with pytest.raises(ValueError, match="KEV"):
        parse_kev_feed({"oops": []})


def test_epss_scores() -> None:
    score = EpssScore.model_validate(
        {"cve": "CVE-2021-44228", "epss": "0.999990000", "percentile": "1.0", "date": "2026-10-20"}
    )
    assert score.epss == Decimal("0.999990000")
    with pytest.raises(ValidationError):
        EpssScore.model_validate(
            {"cve": "CVE-2021-44228", "epss": "2", "percentile": "1", "date": "2026-10-20"}
        )
