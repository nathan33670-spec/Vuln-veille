"""What watch connectors return: plain-text findings with their provenance.

Everything here is untrusted (collected content): text only (markup removed), URLs
kept as data, never followed automatically. Storage applies the collected-item rules
(``app.watch.collect``).
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.connectors.base import ConnectorContext
from app.connectors.quotas import QuotaExceededError
from app.net.safe_http import EgressError, SafeResponse


@dataclass(frozen=True)
class Found:
    source: str  # connector kind
    url: str | None
    title: str
    content: str
    author: str = ""
    published_at: datetime | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_item(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "content": self.content,
            "author": self.author,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            **self.extra,
        }


class FetchError(Exception):
    """A watch service answered unexpectedly; ``code`` is safe to store and show."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code[:200]


async def fetch(
    ctx: ConnectorContext,
    method: str,
    url: str,
    *,
    ok: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> SafeResponse:
    """One request through the connector: quota first, egress rules, expected status."""
    try:
        if ctx.quotas is not None:
            await ctx.quotas.consume()
        response = await ctx.http.request(method, url, **kwargs)
    except QuotaExceededError as exc:
        raise FetchError(f"quota_exceeded: {exc.window}") from None
    except EgressError as exc:
        raise FetchError(f"egress: {exc.code}") from None
    if response.status_code not in ok:
        raise FetchError(f"http_{response.status_code}")
    return response


def json_of(response: SafeResponse) -> Any:
    try:
        return response.json()
    except ValueError:
        raise FetchError("invalid_json") from None


def as_dict(value: Any) -> dict[str, Any]:
    """A JSON object from a service, or an empty one: never trusted to have a shape."""
    return value if isinstance(value, dict) else {}


def from_timestamp(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def from_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
