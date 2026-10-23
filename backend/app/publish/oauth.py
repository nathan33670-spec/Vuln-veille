"""OAuth2 client credentials: the access token of a publication connector.

Tokens are kept in the worker's memory only, until shortly before they expire, keyed
by connector and configuration version; never in Redis, the database or a log.
"""

import base64
import time
from urllib.parse import urlencode

from app.net.safe_http import EgressError, SafeHttpClient
from app.publish.config import HttpGenericConfig
from app.publish.context import PublishError

MARGIN_S = 60
DEFAULT_TTL_S = 300
MAX_TTL_S = 86_400
_CACHE: dict[tuple[str, int], tuple[str, float]] = {}


async def oauth_token(
    http: SafeHttpClient,
    config: HttpGenericConfig,
    secrets: dict[str, str],
    *,
    cache_key: tuple[str, int],
    now: float | None = None,
) -> str:
    moment = now if now is not None else time.monotonic()
    cached = _CACHE.get(cache_key)
    if cached and cached[1] > moment:
        return cached[0]
    client_id, client_secret = secrets.get("client_id"), secrets.get("client_secret")
    if not client_id or not client_secret or not config.auth.endpoint_url:
        raise PublishError("missing_secret:client_id")
    form = {"grant_type": "client_credentials"}
    if config.auth.scope:
        form["scope"] = config.auth.scope
    if config.auth.audience:
        form["audience"] = config.auth.audience
    pair = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    try:
        response = await http.request(
            "POST",
            config.auth.endpoint_url,
            headers={
                "Authorization": f"Basic {pair}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            content=urlencode(form).encode(),
        )
    except EgressError as exc:
        raise PublishError(f"oauth_failed:{exc.code}") from None
    if not 200 <= response.status_code < 300:  # noqa: PLR2004
        raise PublishError(f"oauth_failed:http_{response.status_code}")
    try:
        data = response.json()
        token = str(data["access_token"])
        ttl = int(data.get("expires_in") or DEFAULT_TTL_S)
    except (ValueError, KeyError, TypeError):
        raise PublishError("oauth_failed:invalid_response") from None
    _CACHE[cache_key] = (token, moment + max(0, min(ttl, MAX_TTL_S) - MARGIN_S))
    return token


def forget(cache_key: tuple[str, int]) -> None:
    """A rejected token (401) is dropped so the next attempt asks for a new one."""
    _CACHE.pop(cache_key, None)
