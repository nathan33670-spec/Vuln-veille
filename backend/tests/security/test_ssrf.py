"""SSRF suite for SafeHttpClient (SECURITY.md §4.6, threat S9).

Everything runs offline: a fake resolver plays DNS and httpx's MockTransport plays
the servers. A request that must be refused must never reach the transport.
"""

import asyncio
import gzip
import zlib
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from app.net.safe_http import (
    MIB,
    EgressDeniedError,
    EgressError,
    EgressPolicy,
    ResponseRejectedError,
    SafeHttpClient,
    egress_client,
    private_networks,
)
from tests.conftest import make_settings

PUBLIC_IP = "93.184.215.14"

Handler = Callable[[httpx.Request], httpx.Response]


def respond(
    status: int = 200, body: bytes | str = b"", headers: dict[str, str] | None = None
) -> httpx.Response:
    """A streamed response, as real transports return (never pre-read)."""
    data = body.encode() if isinstance(body, str) else body
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(data))


def resolver_for(table: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    async def resolve(host: str, port: int) -> list[str]:
        if host not in table:
            raise OSError("no such host")
        return table[host]

    return resolve


class Recorder:
    def __init__(self, handler: Handler | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.handler = handler or (lambda _: respond(200, "ok"))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def client(
    recorder: Recorder,
    table: dict[str, list[str]] | None = None,
    *,
    proxy: str | None = None,
    **policy: object,
) -> SafeHttpClient:
    return SafeHttpClient(
        EgressPolicy(**policy),  # type: ignore[arg-type]
        proxy=proxy,
        resolver=resolver_for(table or {"example.org": [PUBLIC_IP]}),
        transport=httpx.MockTransport(recorder),
    )


BLOCKED = [
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.1",
    "172.16.5.4",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",  # noqa: S104 - an address the client must refuse
    "224.0.0.1",
    "255.255.255.255",
    "198.18.0.1",
    "192.0.2.10",
    "240.0.0.1",
    "::1",
    "::",
    "fc00::1",
    "fd12:3456::1",
    "fe80::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:10.0.0.1",
    "2002:7f00:1::1",
    "2001::1",
    "64:ff9b::7f00:1",
    "2001:db8::1",
]


@pytest.mark.parametrize("address", BLOCKED)
async def test_internal_addresses_are_refused_after_resolution(address: str) -> None:
    recorder = Recorder()
    with pytest.raises(EgressDeniedError) as exc:
        await client(recorder, {"evil.example": [address]}).get("https://evil.example/")
    assert exc.value.code == "address_not_allowed"
    assert recorder.requests == []


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "[::1]", "[::ffff:7f00:1]"])
async def test_internal_ip_literals_are_refused(address: str) -> None:
    recorder = Recorder()
    with pytest.raises(EgressDeniedError):
        await client(recorder).get(f"https://{address}/latest/meta-data/")
    assert recorder.requests == []


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "0177.0.0.1", "127.1"])
async def test_numeric_host_spellings_are_judged_on_what_they_resolve_to(host: str) -> None:
    # The system resolver turns these into 127.0.0.1; validation runs on the result.
    recorder = Recorder()
    with pytest.raises(EgressDeniedError):
        await client(recorder, {host: ["127.0.0.1"]}).get(f"https://{host}/")
    assert recorder.requests == []


async def test_one_internal_address_in_the_answer_is_enough_to_refuse() -> None:
    recorder = Recorder()
    with pytest.raises(EgressDeniedError):
        await client(recorder, {"rebind.example": [PUBLIC_IP, "10.0.0.7"]}).get(
            "https://rebind.example/"
        )
    assert recorder.requests == []


async def test_direct_mode_pins_the_validated_address() -> None:
    recorder = Recorder()
    response = await client(recorder).get("https://example.org/feed?x=1")
    assert response.status_code == 200
    sent = recorder.requests[0]
    assert sent.url.host == PUBLIC_IP
    assert sent.headers["host"] == "example.org"
    assert sent.extensions["sni_hostname"] == "example.org"
    assert sent.url.raw_path == b"/feed?x=1"
    assert response.url == "https://example.org/feed?x=1"


async def test_proxy_mode_leaves_name_resolution_to_the_proxy() -> None:
    async def no_dns(host: str, port: int) -> list[str]:
        raise AssertionError("workers have no DNS: the proxy resolves")

    recorder = Recorder()
    egress = SafeHttpClient(
        EgressPolicy(),
        proxy="http://smokescreen:4750",
        resolver=no_dns,
        transport=httpx.MockTransport(recorder),
    )
    await egress.get("https://example.org/")
    assert recorder.requests[0].url.host == "example.org"  # tunnelled by name, not pinned
    assert "sni_hostname" not in recorder.requests[0].extensions
    for literal in ("10.1.1.1", "169.254.169.254", "[::1]"):
        with pytest.raises(EgressDeniedError):
            await egress.get(f"https://{literal}/")
    with pytest.raises(EgressDeniedError):
        await egress.get("http://example.org/")  # URL policy still applies
    assert len(recorder.requests) == 1


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://example.org/", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("gopher://example.org/", "scheme_not_allowed"),
        ("ftp://example.org/", "scheme_not_allowed"),
        ("https://example.org:22/", "port_not_allowed"),
        ("https://example.org:6379/", "port_not_allowed"),
        ("https://user:pass@example.org/", "credentials_in_url"),
        ("https://unknown.example/", "dns_failure"),
    ],
)
async def test_url_policy(url: str, code: str) -> None:
    recorder = Recorder()
    with pytest.raises(EgressDeniedError) as exc:
        await client(recorder).get(url)
    assert exc.value.code == code
    assert recorder.requests == []


async def test_http_only_when_allowed() -> None:
    recorder = Recorder()
    await client(recorder, allow_http=True).get("http://example.org/")
    assert recorder.requests[0].url.scheme == "http"


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("api.github.com", True),
        ("API.GitHub.com.", True),
        ("evilapi.github.com", False),
        ("api.github.com.evil.example", False),
        ("feeds.example.org", True),
        ("deep.feeds.example.org", True),
        ("example.org", False),
        ("badexample.org", False),
    ],
)
async def test_declared_domains(host: str, allowed: bool) -> None:
    recorder = Recorder()
    egress = client(
        recorder,
        {host.lower().rstrip("."): [PUBLIC_IP]},
        allowed_domains=("api.github.com", "*.example.org"),
    )
    if allowed:
        await egress.get(f"https://{host}/")
        assert len(recorder.requests) == 1
    else:
        with pytest.raises(EgressDeniedError) as exc:
            await egress.get(f"https://{host}/")
        assert exc.value.code == "domain_not_allowed"


def redirecting(location: str, status: int = 302) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "example.org":
            return httpx.Response(status, headers={"location": location})
        return respond(200, "landed")

    return handler


async def test_redirect_to_an_internal_address_is_refused() -> None:
    recorder = Recorder(redirecting("https://metadata.example/latest/"))
    egress = client(recorder, {"example.org": [PUBLIC_IP], "metadata.example": ["169.254.169.254"]})
    with pytest.raises(EgressDeniedError) as exc:
        await egress.get("https://example.org/")
    assert exc.value.code == "address_not_allowed"
    assert len(recorder.requests) == 1


async def test_redirect_to_an_internal_ip_literal_is_refused() -> None:
    recorder = Recorder(redirecting("https://127.0.0.1:443/admin"))
    with pytest.raises(EgressDeniedError):
        await client(recorder).get("https://example.org/")
    assert len(recorder.requests) == 1


async def test_https_never_downgrades() -> None:
    recorder = Recorder(redirecting("http://example.org/plain"))
    with pytest.raises(EgressDeniedError) as exc:
        await client(recorder, allow_http=True).get("https://example.org/")
    assert exc.value.code == "https_downgrade"


async def test_redirect_loops_are_bounded() -> None:
    recorder = Recorder(lambda _: respond(302, headers={"location": "/again"}))
    with pytest.raises(EgressDeniedError) as exc:
        await client(recorder).get("https://example.org/")
    assert exc.value.code == "too_many_redirects"
    assert len(recorder.requests) == 6  # the request and 5 redirects


async def test_credentials_stay_on_their_origin() -> None:
    recorder = Recorder(redirecting("https://other.example/next"))
    egress = client(recorder, {"example.org": [PUBLIC_IP], "other.example": [PUBLIC_IP]})
    response = await egress.get(
        "https://example.org/", headers={"Authorization": "Bearer t0ken", "apiKey": "k3y"}
    )
    assert response.text == "landed"
    assert response.redirects == ("https://example.org/",)
    first, second = recorder.requests
    assert first.headers["authorization"] == "Bearer t0ken"
    assert "authorization" not in second.headers
    assert "apikey" not in second.headers


async def test_same_origin_redirect_keeps_credentials_and_303_becomes_get() -> None:
    recorder = Recorder(
        lambda r: (
            respond(303, headers={"location": "/done"})
            if r.url.path == "/submit"
            else respond(200, "done")
        )
    )
    await client(recorder).post(
        "https://example.org/submit", json_body={"a": 1}, headers={"Authorization": "t"}
    )
    second = recorder.requests[1]
    assert second.method == "GET"
    assert second.headers["authorization"] == "t"
    assert second.content == b""


async def test_caller_cannot_override_the_host_header() -> None:
    recorder = Recorder()
    await client(recorder).get("https://example.org/", headers={"Host": "internal.local"})
    assert recorder.requests[0].headers["host"] == "example.org"


async def test_declared_length_over_the_limit_is_refused() -> None:
    recorder = Recorder(lambda _: respond(200, headers={"content-length": str(2 * MIB)}))
    with pytest.raises(ResponseRejectedError) as exc:
        await client(recorder, max_bytes=MIB).get("https://example.org/")
    assert exc.value.code == "response_too_large"


async def test_streamed_body_over_the_limit_is_refused() -> None:
    async def stream() -> AsyncIterator[bytes]:
        for _ in range(64):
            yield b"x" * 65536

    recorder = Recorder(lambda _: httpx.Response(200, content=stream()))
    with pytest.raises(ResponseRejectedError):
        await client(recorder, max_bytes=MIB).get("https://example.org/")


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
async def test_decompression_bombs_are_stopped_at_the_limit(encoding: str) -> None:
    zeros = b"\0" * (64 * MIB)
    bomb = gzip.compress(zeros) if encoding == "gzip" else zlib.compress(zeros)
    assert len(bomb) < MIB
    recorder = Recorder(lambda _: respond(200, bomb, {"content-encoding": encoding}))
    with pytest.raises(ResponseRejectedError) as exc:
        await client(recorder, max_bytes=MIB).get("https://example.org/")
    assert exc.value.code == "response_too_large"


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "raw-deflate"])
async def test_compressed_bodies_are_decoded(encoding: str) -> None:
    body = b'{"vulnerabilities": []}'
    if encoding == "gzip":
        data = gzip.compress(body)
    elif encoding == "deflate":
        data = zlib.compress(body)
    else:
        packer = zlib.compressobj(wbits=-15)
        data = packer.compress(body) + packer.flush()
    header = "deflate" if encoding == "raw-deflate" else encoding
    recorder = Recorder(lambda _: respond(200, data, {"content-encoding": header}))
    response = await client(recorder).get("https://example.org/")
    assert response.json() == {"vulnerabilities": []}


@pytest.mark.parametrize("encoding", ["br", "zstd", "gzip, gzip", "compress"])
async def test_other_encodings_are_refused(encoding: str) -> None:
    recorder = Recorder(lambda _: respond(200, headers={"content-encoding": encoding}))
    with pytest.raises(ResponseRejectedError) as exc:
        await client(recorder).get("https://example.org/")
    assert exc.value.code == "unsupported_encoding"
    assert recorder.requests[0].headers["accept-encoding"] == "gzip, deflate"


async def test_content_types_are_checked_when_declared() -> None:
    html = Recorder(lambda _: respond(200, headers={"content-type": "text/html"}))
    with pytest.raises(ResponseRejectedError) as exc:
        await client(html, allowed_content_types=("application/json",)).get("https://example.org/")
    assert exc.value.code == "unexpected_content_type"
    vendor = Recorder(lambda _: respond(200, headers={"content-type": "application/vnd.api+json"}))
    await client(vendor, allowed_content_types=("application/json",)).get("https://example.org/")


async def test_total_deadline_bounds_slow_servers() -> None:
    async def slow(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200)

    egress = SafeHttpClient(
        EgressPolicy(total_timeout=0.2),
        proxy=None,
        resolver=resolver_for({"example.org": [PUBLIC_IP]}),
        transport=httpx.MockTransport(slow),
    )
    with pytest.raises(EgressError) as exc:
        await egress.get("https://example.org/")
    assert exc.value.code == "timeout"


async def test_granted_private_ranges_never_include_loopback_or_metadata() -> None:
    granted = private_networks(["10.20.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
    recorder = Recorder()
    egress = client(
        recorder,
        {
            "misp.internal": ["10.20.1.5"],
            "lo.internal": ["127.0.0.1"],
            "md.internal": ["169.254.169.254"],
        },
        private_networks=granted,
    )
    await egress.get("https://misp.internal/")
    for host in ("lo.internal", "md.internal"):
        with pytest.raises(EgressDeniedError):
            await egress.get(f"https://{host}/")
    assert len(recorder.requests) == 1


async def test_malformed_redirect_targets_are_refused() -> None:
    # httpx or our own parser refuses it; either way nothing is sent to the target.
    recorder = Recorder(redirecting("https://0177.0.0.1/"))
    with pytest.raises(EgressError):
        await client(recorder).get("https://example.org/")
    assert len(recorder.requests) == 1


async def test_malformed_urls_are_refused() -> None:
    recorder = Recorder()
    with pytest.raises(EgressDeniedError) as exc:
        await client(recorder).get("https://0177.0.0.1/")
    assert exc.value.code == "invalid_url"
    assert recorder.requests == []


async def test_params_are_encoded_into_the_query() -> None:
    recorder = Recorder()
    await client(recorder).get(
        "https://example.org/rest/json/cves/2.0", params={"cveId": "CVE-2026-0001", "x": "a&b"}
    )
    assert recorder.requests[0].url.query == b"cveId=CVE-2026-0001&x=a%26b"


def test_production_never_connects_without_the_egress_proxy() -> None:
    with pytest.raises(EgressError) as exc:
        egress_client(
            make_settings(environment="prod", password_hash_profile="strong"), EgressPolicy()
        )
    assert exc.value.code == "egress_proxy_required"
    proxied = egress_client(
        make_settings(
            environment="prod",
            password_hash_profile="strong",
            egress_proxy_url="http://smokescreen:4750",
        ),
        EgressPolicy(),
    )
    assert proxied.proxy == "http://smokescreen:4750"


async def test_proxy_refusals_are_reported_as_denials() -> None:
    def refuse(_: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("403 Forbidden")

    egress = SafeHttpClient(
        EgressPolicy(), proxy="http://smokescreen:4750", transport=httpx.MockTransport(refuse)
    )
    with pytest.raises(EgressDeniedError) as exc:
        await egress.get("https://not-allowed.example/")
    assert exc.value.code == "proxy_denied"
