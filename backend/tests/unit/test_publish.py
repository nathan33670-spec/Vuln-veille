"""Publication connector, without a database (spec 05, ADR-030): mapping, configuration,
the exact request for every authentication type, CSAF export, client certificates."""

import base64
import copy
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from app.bulletins.models import Bulletin, BulletinRevision, BulletinSettings
from app.net.safe_http import EgressError, EgressPolicy, SafeHttpClient
from app.publish.config import HttpGenericConfig
from app.publish.context import Publication, PublishError, publication_context
from app.publish.csaf import csaf_document
from app.publish.mapping import build_payload, context_paths, validate_mapping
from app.publish.request import MASK, build_request
from app.technologies.models import Technology
from app.vulns.models import Vulnerability

NOW = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
HOSTILE = "{{ 7 | plus: 7 }} <script>alert(1)</script>"
MAPPING: dict[str, Any] = {
    "title": {"path": "bulletin.title"},
    "severity": {
        "path": "bulletin.severity",
        "map": {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"},
    },
    "cves": {"path": "cves"},
    "content": {"path": "revision.markdown"},
    "published": {"path": "bulletin.published_at", "format": "date"},
    "source": {"const": "VOC"},
    "summary": {"template": "{{ bulletin.fields.summary | truncate: 40 }}"},
    "references": {"path": "bulletin.fields.references[].url"},
    "nested": [{"score": {"path": "bulletin.fields.cvss.score", "format": "string"}}],
    "missing": {"path": "bulletin.fields.nothing", "default": "n/a"},
}
BASE: dict[str, Any] = {
    "request": {
        "base_url": "https://api.partner.example",
        "path": "/v2/advisories",
        "update": {"method": "PUT", "path": "/v2/advisories/{{ remote_id }}"},
        "headers": {"X-Source": "vuln-veille"},
    },
    "body": {"format": "json", "mapping": MAPPING},
    "response": {"remote_id_path": "data.id"},
}


def _config(**auth: Any) -> HttpGenericConfig:
    raw = copy.deepcopy(BASE)
    if auth:
        raw["auth"] = auth
    return HttpGenericConfig.model_validate(raw)


def _publication(**settings: str) -> Publication:
    bulletin = Bulletin(
        id=uuid.UUID(int=1),
        workspace_id=uuid.UUID(int=2),
        ref="VOC-2026-0007",
        language="fr",
        title="RCE",
        status="published",
        severity="critical",
        tlp="GREEN",
        published_at=NOW,
        approved_at=NOW - timedelta(minutes=5),
    )
    revision = BulletinRevision(
        id=uuid.UUID(int=3),
        bulletin_id=bulletin.id,
        rev_no=2,
        fields={
            "title": "RCE dans Exemple",
            "summary": f"Une faille grave. {HOSTILE}",
            "cves": ["CVE-2026-0001"],
            "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "affected_products": [{"vendor": "exemple", "product": "serveur", "versions": "< 2.4"}],
            "recommendations": "Mettre à jour.",
            "references": [
                {"title": "Avis", "url": "https://exemple.org/avis"},
                {"title": "Piège", "url": "javascript:alert(1)"},
            ],
        },
        rendered_markdown="# RCE dans Exemple\n",
        rendered_html="<h1>RCE dans Exemple</h1>",
        content_hash="a" * 64,
        created_at=NOW - timedelta(minutes=10),
    )
    vulnerability = Vulnerability(
        id=uuid.UUID(int=4),
        ref="VV-2026-0001",
        cve_id="CVE-2026-0001",
        title="RCE",
        exploitation_status="exploited_itw",
        patch_status="available",
    )
    technology = Technology(vendor="exemple", product="serveur", display_name="Exemple Serveur")
    return Publication(
        bulletin=bulletin,
        revision=revision,
        vulnerabilities=[vulnerability],
        technologies=[technology],
        workspace_slug="voc",
        settings=BulletinSettings(
            workspace_id=bulletin.workspace_id,
            ref_prefix="VOC",
            csaf_publisher_name=settings.get("name", ""),
            csaf_publisher_namespace=settings.get("namespace", ""),
            csaf_publisher_category="coordinator",
        ),
    )


# --- Mapping ---------------------------------------------------------------------


def test_mapping_builds_json_and_never_compiles_data() -> None:
    assert validate_mapping(MAPPING) == []
    payload = build_payload(MAPPING, publication_context(_publication()))
    assert payload["severity"] == "P1"
    assert payload["cves"] == ["CVE-2026-0001"]
    assert payload["published"] == "2026-10-22"
    assert payload["source"] == "VOC"
    assert payload["references"] == ["https://exemple.org/avis", "javascript:alert(1)"]
    assert payload["nested"] == [{"score": "9.8"}]
    assert payload["missing"] == "n/a"
    # A value that looks like a template stays text: data is never compiled.
    assert payload["summary"].startswith("Une faille grave. {{ 7")
    assert "14" not in payload["summary"]


@pytest.mark.parametrize(
    ("mapping", "code"),
    [
        ({"a": "bare"}, "bare_value"),
        ({"a": {"path": "bulletin[", "map": {}}}, "invalid_path"),
        ({"a": {"template": "{% include 'x' %}"}}, "invalid_template"),
        ({"a": {"const": 1, "format": "upper"}}, "leaf_options_need_path"),
        ({"a": {"path": "x", "format": "rot13"}}, "invalid_format"),
        ({"a": {"path": "x", "other": 1}}, "ambiguous_leaf"),
        ("not a tree", "not_a_tree"),
    ],
)
def test_mapping_errors(mapping: Any, code: str) -> None:
    assert code in [e["code"] for e in validate_mapping(mapping)]


def test_mapping_limits() -> None:
    deep: dict[str, Any] = {"v": {"const": 1}}
    for _ in range(15):
        deep = {"n": deep}
    assert "too_deep" in [e["code"] for e in validate_mapping(deep)]
    wide = {f"k{i}": {"const": i} for i in range(600)}
    assert "too_many_nodes" in [e["code"] for e in validate_mapping(wide)]


def test_context_paths_for_completion() -> None:
    paths = context_paths(publication_context(_publication()))
    assert "bulletin.fields.summary" in paths
    assert "vulnerabilities[].cve_id" in paths


# --- Configuration ---------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"request": {"base_url": "ftp://x.example"}},
        {"request": {"base_url": "https://user:pw@x.example"}},
        {"request": {"base_url": "https://x.example", "headers": {"Authorization": "x"}}},
        {"request": {"base_url": "https://x.example", "headers": {"X-Api-Token": "x"}}},
        {"request": {"base_url": "https://x.example", "headers": {"X-A": "a\r\nB: b"}}},
        {"request": {"base_url": "https://x.example", "path": "https://evil.example/"}},
        {"auth": {"type": "oauth2_client_credentials"}},
        {"body": {"format": "json"}},
        {"response": {"success_status": [302]}},
        {"retry": {"retry_on": [404]}},
    ],
)
def test_invalid_configurations(change: dict[str, Any]) -> None:
    raw = {**copy.deepcopy(BASE), **change}
    with pytest.raises(ValidationError):
        HttpGenericConfig.model_validate(raw)


def test_hosts_include_the_token_endpoint() -> None:
    config = _config(
        type="oauth2_client_credentials", endpoint_url="https://auth.partner.example/t"
    )
    assert config.hosts() == ("api.partner.example", "auth.partner.example")
    assert _config().hosts() == ("api.partner.example",)


# --- Requests --------------------------------------------------------------------


def _request(config: HttpGenericConfig, **kwargs: Any) -> Any:
    return build_request(config, _publication(), connector_id="c1", now=1_700_000_000, **kwargs)


def test_dry_run_masks_every_credential() -> None:
    for auth in (
        {"type": "bearer"},
        {"type": "basic"},
        {"type": "api_key", "key_name": "X-Key"},
        {"type": "oauth2_client_credentials", "endpoint_url": "https://auth.partner.example/t"},
        {"type": "hmac"},
    ):
        shown = _request(_config(**auth)).redacted()
        assert MASK in json.dumps(shown["headers"], ensure_ascii=False), auth


def test_real_request_and_its_redacted_journal() -> None:
    secrets = {"credential": "s3cr3t-t0ken"}
    prepared = _request(_config(type="bearer"), secrets=secrets)
    assert prepared.method == "POST"
    assert prepared.url == "https://api.partner.example/v2/advisories"
    assert prepared.headers["Authorization"] == "Bearer s3cr3t-t0ken"
    assert prepared.headers["X-Source"] == "vuln-veille"
    assert prepared.headers["Idempotency-Key"] == prepared.idempotency_key
    assert "s3cr3t-t0ken" not in json.dumps(prepared.redacted())
    # Same revision, same connector: the same key on every retry.
    assert _request(_config(type="bearer"), secrets=secrets).idempotency_key == (
        prepared.idempotency_key
    )


def test_update_uses_the_remote_id_encoded() -> None:
    prepared = _request(_config(), remote_id="a/../b c", secrets={})
    assert (prepared.method, prepared.mode) == ("PUT", "update")
    assert prepared.url == "https://api.partner.example/v2/advisories/a%2F..%2Fb%20c"


def test_basic_api_key_query_and_missing_secret() -> None:
    basic = _request(_config(type="basic"), secrets={"username": "u", "password": "p4ssw0rd"})
    assert basic.headers["Authorization"] == "Basic " + base64.b64encode(b"u:p4ssw0rd").decode()
    query = _request(
        _config(type="api_key", key_location="query", key_name="apikey"),
        secrets={"credential": "k3y-value"},
    )
    assert query.url.endswith("?apikey=k3y-value")
    assert "k3y-value" not in query.redacted()["url"]
    with pytest.raises(PublishError, match="missing_secret:credential"):
        _request(_config(type="bearer"), secrets={})


def test_hmac_signature_is_verifiable() -> None:
    config = _config(type="hmac", timestamp_header="X-Timestamp")
    prepared = _request(config, secrets={"signing_key": "k-e-y-1234"})
    stamp = prepared.headers["X-Timestamp"]
    expected = hmac.new(b"k-e-y-1234", f"{stamp}.".encode() + prepared.body, hashlib.sha256)
    assert prepared.headers["X-Signature"] == "sha256=" + expected.hexdigest()


def test_markdown_and_csaf_bodies() -> None:
    raw = copy.deepcopy(BASE)
    raw["body"] = {"format": "markdown"}
    prepared = _request(HttpGenericConfig.model_validate(raw), secrets={})
    assert prepared.headers["Content-Type"].startswith("text/markdown")
    assert prepared.body == b"# RCE dans Exemple\n"
    raw["body"] = {"format": "csaf"}
    with pytest.raises(PublishError, match="csaf_publisher_missing"):
        _request(HttpGenericConfig.model_validate(raw), secrets={})


# --- CSAF ------------------------------------------------------------------------


def test_csaf_document() -> None:
    publication = _publication(name="CERT Exemple", namespace="https://cert.example.org")
    csaf = csaf_document(publication)
    document = csaf["document"]
    assert document["category"] == "csaf_security_advisory"
    assert document["csaf_version"] == "2.0"
    assert document["publisher"] == {
        "category": "coordinator",
        "name": "CERT Exemple",
        "namespace": "https://cert.example.org",
    }
    assert document["distribution"]["tlp"]["label"] == "GREEN"
    tracking = document["tracking"]
    assert (tracking["id"], tracking["status"], tracking["version"]) == (
        "VOC-2026-0007",
        "final",
        "2",
    )
    assert tracking["revision_history"][-1]["number"] == tracking["version"]
    assert tracking["revision_history"][-1]["date"] == tracking["current_release_date"]
    assert tracking["initial_release_date"] <= tracking["current_release_date"]
    assert [r["url"] for r in document["references"]] == ["https://exemple.org/avis"]
    branch = csaf["product_tree"]["branches"][0]
    assert (branch["category"], branch["name"]) == ("vendor", "exemple")
    product = branch["branches"][0]["branches"][0]
    assert product["category"] == "product_version_range"
    pid = product["product"]["product_id"]
    vulnerability = csaf["vulnerabilities"][0]
    assert vulnerability["cve"] == "CVE-2026-0001"
    assert vulnerability["product_status"]["known_affected"] == [pid]
    assert vulnerability["remediations"][0]["category"] == "vendor_fix"
    score = vulnerability["scores"][0]["cvss_v3"]
    assert (score["version"], score["baseSeverity"]) == ("3.1", "CRITICAL")


# --- Client certificates ---------------------------------------------------------


def _pem_pair() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vuln-veille-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem


def test_client_certificate_loads_from_memory() -> None:
    cert, key = _pem_pair()
    SafeHttpClient(EgressPolicy(client_cert_pem=cert, client_key_pem=key), proxy=None)
    with pytest.raises(EgressError, match="client_certificate_invalid"):
        SafeHttpClient(EgressPolicy(client_cert_pem=cert, client_key_pem="nope"), proxy=None)
