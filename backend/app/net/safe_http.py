"""SafeHttpClient: every outbound HTTP request goes through it (SECURITY.md §4.6).

Barriers, per request and per redirect hop:
1. URL policy: scheme (https; http only if allowed), port, declared domains, no
   credentials in the URL;
2. addresses: IP literals are always checked. In direct mode the client resolves the
   name itself and refuses if *any* address is not public (or inside a range an
   administrator granted), then pins the validated IP (original Host and SNI,
   certificate checked against the host name): DNS rebinding cannot redirect it;
3. proxy mode (production workers, which have no DNS or route to the Internet):
   the tunnel is opened by host name and smokescreen resolves it, then enforces the
   address ranges and the domain allow-list on the address it actually dials;
4. redirects followed manually (5 at most), each hop re-validated; credentials are
   dropped when the origin changes and https never downgrades to http;
5. bounds: total deadline, connect/read timeouts, response size on the wire and after
   decompression (gzip and deflate only, decoded here with a hard output limit),
   expected content types.
"""

import asyncio
import ipaddress
import json
import os
import socket
import ssl
import zlib
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import certifi
import httpx

from app.core.config import Settings
from app.net.addresses import IPAddress, IPNetwork, is_allowed, parse_address

MIB = 1024 * 1024
SEE_OTHER = 303
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DEFAULT_SECRET_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "x-api-key", "apikey", "api-key"}
)
USER_AGENT = (
    "Vuln-Veille/0.1 (vulnerability watch; +https://github.com/nathan33670-spec/Vuln-veille)"
)

Resolver = Callable[[str, int], Awaitable[list[str]]]


class EgressError(Exception):
    """Base error; ``code`` is a stable machine-readable reason (never secret)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class EgressDeniedError(EgressError):
    """The destination is not allowed by the policy."""


class ResponseRejectedError(EgressError):
    """The response breaks a bound (size, encoding, content type)."""


@dataclass(frozen=True)
class EgressPolicy:
    # Exact names ("api.github.com") or subdomain wildcards ("*.example.org").
    # Empty means any public host (the proxy allow-list still applies).
    allowed_domains: tuple[str, ...] = ()
    allow_http: bool = False
    allowed_ports: frozenset[int] = frozenset({80, 443})
    private_networks: tuple[IPNetwork, ...] = ()
    max_bytes: int = 10 * MIB
    max_redirects: int = 5
    connect_timeout: float = 5.0
    read_timeout: float = 20.0
    total_timeout: float = 60.0
    allowed_content_types: tuple[str, ...] = ()
    ca_bundle_pem: str | None = None
    # mTLS: PEM certificate chain and key, loaded from memory (never written to disk).
    client_cert_pem: str | None = field(default=None, repr=False)
    client_key_pem: str | None = field(default=None, repr=False)
    secret_headers: frozenset[str] = field(default=DEFAULT_SECRET_HEADERS)

    def domain_allowed(self, host: str) -> bool:
        if not self.allowed_domains:
            return True
        for entry in self.allowed_domains:
            rule = entry.lower().rstrip(".")
            if rule.startswith("*."):
                if host.endswith(rule[1:]) and host != rule[2:]:
                    return True
            elif host == rule:
                return True
        return False


@dataclass(frozen=True)
class SafeResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str
    redirects: tuple[str, ...] = ()

    @property
    def text(self) -> str:
        charset = httpx.Response(200, headers=self.headers).charset_encoding or "utf-8"
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


class _BoundedDecoder:
    """gzip/deflate decoding that never produces more than ``limit`` bytes."""

    def __init__(self, encoding: str, limit: int) -> None:
        self.limit = limit
        self.size = 0
        self.raw_deflate_fallback = encoding == "deflate"
        # 47 = auto-detect zlib or gzip headers.
        self.inflater: Any = zlib.decompressobj(47) if encoding in ("gzip", "deflate") else None

    def feed(self, data: bytes) -> bytes:
        if self.inflater is None:
            return self._count(data)
        try:
            out = self._inflate(data)
        except zlib.error:
            if not self.raw_deflate_fallback or self.size:
                raise ResponseRejectedError("bad_encoding") from None
            self.raw_deflate_fallback = False
            self.inflater = zlib.decompressobj(-15)
            out = self._inflate(data)
        return out

    def _inflate(self, data: bytes) -> bytes:
        chunks = []
        while data:
            chunk = self.inflater.decompress(data, self.limit - self.size + 1)
            chunks.append(self._count(chunk))
            data = self.inflater.unconsumed_tail
        return b"".join(chunks)

    def _count(self, data: bytes) -> bytes:
        self.size += len(data)
        if self.size > self.limit:
            raise ResponseRejectedError("response_too_large")
        return data


def _parse(url: str, base: httpx.URL | None = None) -> httpx.URL:
    """Parses a URL or a redirect target; malformed input is a refusal, not a crash."""
    try:
        return base.join(url) if base is not None else httpx.URL(url)
    except (httpx.InvalidURL, ValueError) as exc:
        raise EgressDeniedError("invalid_url") from exc


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    return (url.scheme, url.host, url.port)


def _media_type(headers: httpx.Headers) -> str:
    return str(headers.get("content-type", "")).split(";", 1)[0].strip().lower()


class SafeHttpClient:
    def __init__(
        self,
        policy: EgressPolicy,
        *,
        proxy: str | None,
        resolver: Resolver = system_resolver,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.policy = policy
        self.proxy = proxy
        self.resolver = resolver
        self._transport = transport  # tests only: replaces the network
        self._ssl = ssl.create_default_context(
            cafile=None if policy.ca_bundle_pem else certifi.where(),
            cadata=policy.ca_bundle_pem,
        )
        if policy.client_cert_pem and policy.client_key_pem:
            _load_client_certificate(self._ssl, policy.client_cert_pem, policy.client_key_pem)

    async def get(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("POST", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str | int] | None = None,
        json_body: Any = None,
        content: bytes | None = None,
    ) -> SafeResponse:
        try:
            async with asyncio.timeout(self.policy.total_timeout):
                return await self._follow(method, url, headers, params, json_body, content)
        except TimeoutError as exc:
            raise EgressError("timeout") from exc
        except httpx.TimeoutException as exc:
            raise EgressError("timeout") from exc
        except httpx.ProxyError as exc:
            # smokescreen refused the destination (allow-list or address range).
            raise EgressDeniedError("proxy_denied") from exc
        except httpx.HTTPError as exc:
            raise EgressError("network_error", type(exc).__name__) from exc

    async def _follow(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None,
        params: Mapping[str, str | int] | None,
        json_body: Any,
        content: bytes | None,
    ) -> SafeResponse:
        current = _parse(url)
        if params:
            current = current.copy_merge_params(params)
        base_headers = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
        if json_body is not None:
            content = json.dumps(json_body).encode()
            base_headers.setdefault("content-type", "application/json")
        visited: list[str] = []
        for _ in range(self.policy.max_redirects + 1):
            address = await self._check(current)
            status, response_headers, body = await self._send(
                method, current, address, base_headers, content
            )
            location = response_headers.get("location")
            if status not in REDIRECT_STATUSES or not location:
                return SafeResponse(status, response_headers, body, str(current), tuple(visited))
            visited.append(str(current))
            target = _parse(location, current)
            if current.scheme == "https" and target.scheme == "http":
                raise EgressDeniedError("https_downgrade")
            if _origin(target) != _origin(current):
                base_headers = {
                    k: v
                    for k, v in base_headers.items()
                    if k.lower() not in self.policy.secret_headers
                }
            if status == SEE_OTHER or (status in (301, 302) and method == "POST"):
                method, content = "GET", None
                base_headers = {
                    k: v for k, v in base_headers.items() if k.lower() != "content-type"
                }
            current = target
        raise EgressDeniedError("too_many_redirects")

    async def _check(self, url: httpx.URL) -> IPAddress | None:
        policy = self.policy
        if url.scheme not in (("https", "http") if policy.allow_http else ("https",)):
            raise EgressDeniedError("scheme_not_allowed", url.scheme)
        if url.userinfo:
            raise EgressDeniedError("credentials_in_url")
        host = url.host.lower().rstrip(".")
        if not host:
            raise EgressDeniedError("missing_host")
        port = url.port or (443 if url.scheme == "https" else 80)
        if port not in policy.allowed_ports:
            raise EgressDeniedError("port_not_allowed", str(port))
        if not policy.domain_allowed(host):
            raise EgressDeniedError("domain_not_allowed", host)
        try:
            addresses = [parse_address(host)]
        except ValueError:
            if self.proxy is not None:
                return None  # resolved and checked by the proxy, on the address it dials
            addresses = await self._resolve(host, port)
        # Every address must pass: a mixed answer is how rebinding attacks start.
        for address in addresses:
            if not is_allowed(address, policy.private_networks):
                raise EgressDeniedError("address_not_allowed", host)
        return addresses[0]

    async def _resolve(self, host: str, port: int) -> list[IPAddress]:
        try:
            resolved = await self.resolver(host, port)
        except OSError as exc:
            raise EgressDeniedError("dns_failure", host) from exc
        if not resolved:
            raise EgressDeniedError("dns_failure", host)
        return [parse_address(a) for a in resolved]

    async def _send(
        self,
        method: str,
        url: httpx.URL,
        address: IPAddress | None,
        headers: Mapping[str, str],
        content: bytes | None,
    ) -> tuple[int, httpx.Headers, bytes]:
        """One hop; the body is already decoded (bounded) and redirect bodies dropped."""
        policy = self.policy
        request_headers = {
            "user-agent": USER_AGENT,
            "accept-encoding": "gzip, deflate",
            **headers,
        }
        extensions: dict[str, Any] = {}
        target = url
        if address is not None and self.proxy is None:
            # Direct mode: connect to the validated address, keep Host and SNI.
            request_headers["host"] = url.netloc.decode("ascii")
            if url.scheme == "https":
                extensions["sni_hostname"] = url.host
            target = url.copy_with(host=str(address))
        timeout = httpx.Timeout(
            connect=policy.connect_timeout,
            read=policy.read_timeout,
            write=policy.read_timeout,
            pool=policy.connect_timeout,
        )
        async with httpx.AsyncClient(
            proxy=self.proxy if self._transport is None else None,
            transport=self._transport,
            verify=self._ssl,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            request = client.build_request(
                method, target, headers=request_headers, content=content, extensions=extensions
            )
            response = await client.send(request, stream=True)
            try:
                if response.status_code in REDIRECT_STATUSES:
                    body = b""
                else:
                    self._check_headers(response)
                    body = await self._read(response)
            finally:
                await response.aclose()
        return response.status_code, response.headers, body

    def _check_headers(self, response: httpx.Response) -> None:
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.policy.max_bytes:
            raise ResponseRejectedError("response_too_large")
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("identity", "gzip", "deflate"):
            raise ResponseRejectedError("unsupported_encoding", encoding)
        allowed = self.policy.allowed_content_types
        if allowed and response.is_success:
            media = _media_type(response.headers)
            if not any(media == t or media.endswith("+" + t.split("/")[-1]) for t in allowed):
                raise ResponseRejectedError("unexpected_content_type", media)

    async def _read(self, response: httpx.Response) -> bytes:
        limit = self.policy.max_bytes
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        decoder = _BoundedDecoder(encoding, limit)
        raw_size = 0
        chunks = []
        async for chunk in response.aiter_raw():
            raw_size += len(chunk)
            if raw_size > limit:
                raise ResponseRejectedError("response_too_large")
            chunks.append(decoder.feed(chunk))
        return b"".join(chunks)


def _load_client_certificate(context: ssl.SSLContext, cert_pem: str, key_pem: str) -> None:
    """``load_cert_chain`` reads paths only: anonymous in-memory files stand in for them,
    so the key never touches a disk (Linux ``memfd``)."""
    descriptors = []
    try:
        paths = []
        for name, pem in (("cert", cert_pem), ("key", key_pem)):
            fd = os.memfd_create(f"vv-{name}", os.MFD_CLOEXEC)
            descriptors.append(fd)
            os.write(fd, pem.encode())
            paths.append(f"/proc/self/fd/{fd}")
        context.load_cert_chain(certfile=paths[0], keyfile=paths[1])
    except (ssl.SSLError, ValueError) as exc:
        raise EgressError("client_certificate_invalid") from exc
    finally:
        for fd in descriptors:
            os.close(fd)


def egress_client(settings: Settings, policy: EgressPolicy) -> SafeHttpClient:
    """The client every component must use; production always goes through the proxy."""
    if settings.is_prod and not settings.egress_proxy_url:
        raise EgressError("egress_proxy_required")
    return SafeHttpClient(policy, proxy=settings.egress_proxy_url)


def private_networks(cidrs: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(c, strict=True) for c in cidrs)
