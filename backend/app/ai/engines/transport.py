"""HTTP transports that route the official SDKs through ``SafeHttpClient``.

The SDKs of the providers (``anthropic`` on httpx2, ``google-genai`` on httpx) accept
a caller-supplied HTTP client. Giving them a client whose transport delegates to
``SafeHttpClient`` keeps the non-negotiable egress rules for model calls too: declared
domains only, address checks, the egress proxy, bounded and decoded responses.
"""

from typing import Any

import httpx
import httpx2

from app.net.safe_http import EgressError, SafeHttpClient

# Hop-by-hop or transport headers: SafeHttpClient sets its own.
_DROPPED_REQUEST = frozenset(
    {"host", "content-length", "accept-encoding", "transfer-encoding", "connection"}
)
# The body handed back is already decoded and complete.
_DROPPED_RESPONSE = frozenset({"content-encoding", "content-length", "transfer-encoding"})


class TransportEgressError(Exception):
    """Raised inside the SDK; adapters unwrap it from the SDK's connection error."""

    def __init__(self, error: EgressError) -> None:
        super().__init__(error.code)
        self.error = error


async def _forward(
    safe: SafeHttpClient, method: str, url: str, headers: list[tuple[str, str]], body: bytes
) -> tuple[int, list[tuple[str, str]], bytes]:
    forwarded = {k: v for k, v in headers if k.lower() not in _DROPPED_REQUEST}
    try:
        response = await safe.request(method, url, headers=forwarded, content=body or None)
    except EgressError as exc:
        raise TransportEgressError(exc) from None
    kept = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in _DROPPED_RESPONSE]
    return response.status_code, kept, response.content


class SafeHttpxTransport(httpx.AsyncBaseTransport):
    def __init__(self, safe: SafeHttpClient) -> None:
        self.safe = safe

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        status, headers, content = await _forward(
            self.safe, request.method, str(request.url), request.headers.multi_items(), body
        )
        return httpx.Response(status, headers=headers, content=content, request=request)


class SafeHttpx2Transport(httpx2.AsyncBaseTransport):
    def __init__(self, safe: SafeHttpClient) -> None:
        self.safe = safe

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        body = await request.aread()
        status, headers, content = await _forward(
            self.safe, request.method, str(request.url), request.headers.multi_items(), body
        )
        return httpx2.Response(status, headers=headers, content=content, request=request)


class RefusingSyncTransport(httpx.BaseTransport):
    """The SDKs also build a synchronous client; it must never reach the network."""

    def handle_request(self, request: httpx.Request) -> Any:
        raise RuntimeError("synchronous model calls are not allowed")


def egress_cause(exc: BaseException) -> EgressError | None:
    """The egress refusal behind an SDK connection error, if any."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TransportEgressError):
            return current.error
        current = current.__cause__ or current.__context__
    return None


def safe_httpx_clients(
    safe: SafeHttpClient, timeout: float
) -> tuple[httpx.AsyncClient, httpx.Client]:
    """For SDKs built on httpx: an async client on SafeHttpClient, a sync one that refuses."""
    return (
        httpx.AsyncClient(transport=SafeHttpxTransport(safe), timeout=timeout),
        httpx.Client(transport=RefusingSyncTransport()),
    )


# Network failures an SDK may let through unwrapped.
TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (httpx.HTTPError, httpx2.HTTPError)
