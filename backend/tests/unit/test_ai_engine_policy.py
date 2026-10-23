"""The network policy of an OpenAI-compatible engine (ADR-032): plain HTTP, the
server's own port and an internal CA, but HTTP and the port only towards a private
range an administrator approved."""

import ipaddress

import pytest
from pydantic import ValidationError

from app.ai.engines.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleConnector
from app.net.safe_http import EgressPolicy

MODELS = [{"model_id": "llama3"}]
APPROVED = (ipaddress.ip_network("10.20.0.0/16"),)


def _policy(url: str, approved: bool, ca: str | None = None) -> EgressPolicy:
    config = OpenAICompatibleConfig.model_validate({"base_url": url, "models": MODELS})
    base = EgressPolicy(
        allowed_domains=OpenAICompatibleConnector.egress_for(config),
        private_networks=APPROVED if approved else (),
    )
    secrets = {"ca_bundle": ca} if ca else {}
    return OpenAICompatibleConnector.adjust_policy(config, secrets, base)


def test_http_and_port_only_towards_an_approved_range() -> None:
    local = _policy("http://llm.internal:11434/v1", approved=True)
    assert local.allow_http
    assert 11434 in local.allowed_ports
    unapproved = _policy("http://llm.internal:11434/v1", approved=False)
    assert not unapproved.allow_http
    assert unapproved.allowed_ports == frozenset({80, 443})
    assert not _policy("https://llm.internal/v1", approved=True).allow_http


def test_internal_ca_and_self_hosted_by_default() -> None:
    assert _policy("https://llm.internal/v1", True, ca="-----BEGIN CERT").ca_bundle_pem
    config = OpenAICompatibleConfig.model_validate(
        {"base_url": "https://llm.internal/v1", "models": MODELS}
    )
    assert config.location == "self_hosted"


@pytest.mark.parametrize("url", ["ftp://llm.internal/v1", "file:///etc/passwd"])
def test_other_schemes_refused(url: str) -> None:
    with pytest.raises(ValidationError):
        OpenAICompatibleConfig.model_validate({"base_url": url, "models": MODELS})


def test_secret_slots() -> None:
    assert [s.name for s in OpenAICompatibleConnector.secret_slots] == ["api_key", "ca_bundle"]
