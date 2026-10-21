"""A tiny fake web for connector tests: routes by URL, no network."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from app.net.safe_http import MIB, EgressPolicy, SafeHttpClient

Route = Callable[[httpx.Request], tuple[Any, ...]]


@dataclass(frozen=True)
class RawBody:
    data: bytes
    content_type: str


class FakeWeb:
    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[httpx.Request] = []

    def json(self, url: str, body: Any, status: int = 200) -> None:
        self.routes[url] = lambda _request: (status, body)

    def raw(self, url: str, body: bytes, content_type: str, status: int = 200) -> None:
        self.routes[url] = lambda _request: (status, RawBody(body, content_type))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = f"https://{request.headers['host']}{request.url.path}"
        route = self.routes.get(url)
        if route is None:
            return httpx.Response(404, stream=httpx.ByteStream(b"not found"))
        status, body, *extra = route(request)
        headers = extra[0] if extra else {}
        if isinstance(body, RawBody):
            return httpx.Response(
                status,
                headers={"content-type": body.content_type},
                stream=httpx.ByteStream(body.data),
            )
        data = json.dumps(body).encode()
        return httpx.Response(
            status,
            headers={"content-type": "application/json", **headers},
            stream=httpx.ByteStream(data),
        )

    def client(self, *domains: str) -> SafeHttpClient:
        async def resolve(host: str, port: int) -> list[str]:
            return ["93.184.215.14"]

        return SafeHttpClient(
            EgressPolicy(allowed_domains=domains, max_bytes=64 * MIB),
            proxy=None,
            resolver=resolve,
            transport=httpx.MockTransport(self.handler),
        )

    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]
