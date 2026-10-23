"""The exact request a publication sends, built once for the dry-run and the push.

The body is built as a value and serialised (JSON, CSAF or Markdown); the path is a
Liquid template fed with percent-encoded values only; credentials are added last,
from the connector's secret slots. Without secrets (dry-run on the API side, which
cannot decrypt them) every credential is replaced by a mask, and so is a signature.
"""

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

from app.publish.config import HttpGenericConfig
from app.publish.context import Publication, PublishError, publication_context
from app.publish.csaf import csaf_document
from app.publish.mapping import MappingError, build_payload
from app.workflows.expressions import ExpressionError, compile_template

MASK = "••••••"
MAX_BODY_BYTES = 1024 * 1024
MAX_PATH = 1000


@dataclass(frozen=True)
class PreparedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    mode: str  # "create" or "update"
    idempotency_key: str
    # Values to strip from anything logged (credentials, tokens, signatures).
    sensitive: tuple[str, ...] = field(default=(), repr=False)

    def redacted(self) -> dict[str, Any]:
        """The request as shown to people and stored in the journal: no credential."""
        return {
            "method": self.method,
            "url": redact(self.url, self.sensitive),
            "headers": {k: redact(v, self.sensitive) for k, v in self.headers.items()},
            "body": redact(self.body.decode("utf-8", errors="replace"), self.sensitive),
            "mode": self.mode,
        }


def redact(text: str, sensitive: tuple[str, ...]) -> str:
    for value in sorted(sensitive, key=len, reverse=True):
        if len(value) >= 4:  # noqa: PLR2004 - shorter values would mask ordinary text
            text = text.replace(value, MASK)
            text = text.replace(quote(value, safe=""), MASK)
    return text


def idempotency_key(connector_id: str, publication: Publication, mode: str) -> str:
    """Same bulletin revision to the same connector: the same key, whatever the retry."""
    raw = f"{connector_id}:{publication.bulletin.id}:{publication.revision.content_hash}:{mode}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _path(template: str, publication: Publication, remote_id: str | None) -> str:
    values = {
        "remote_id": quote(remote_id or "", safe=""),
        "bulletin": {
            "id": str(publication.bulletin.id),
            "ref": quote(publication.bulletin.ref, safe=""),
        },
    }
    try:
        path = str(compile_template(template).render(**values))
    except ExpressionError:
        raise PublishError("invalid_path") from None
    if (
        not path.startswith("/")
        or path.startswith("//")
        or len(path) > MAX_PATH
        or any(c in path for c in "?#\\ \r\n\t")
        or "/../" in f"{path}/"
    ):
        raise PublishError("invalid_path")
    return path


def _body(
    config: HttpGenericConfig, publication: Publication, context: dict[str, Any]
) -> tuple[bytes, str]:
    if config.body.format == "markdown":
        return publication.revision.rendered_markdown.encode(), "text/markdown; charset=utf-8"
    if config.body.format == "csaf":
        value: Any = csaf_document(publication)
    else:
        try:
            value = build_payload(config.body.mapping, context)
        except MappingError as exc:
            raise PublishError(f"mapping_failed:{exc.path}") from None
    body = json.dumps(value, ensure_ascii=False).encode()
    return body, "application/json"


def build_request(
    config: HttpGenericConfig,
    publication: Publication,
    *,
    connector_id: str,
    remote_id: str | None = None,
    secrets: Mapping[str, str] | None = None,
    oauth_token: str | None = None,
    now: float | None = None,
) -> PreparedRequest:
    """The request for one publication; ``secrets=None`` builds the masked dry-run."""
    update = remote_id is not None and config.request.update is not None
    mode = "update" if update else "create"
    method = (
        config.request.update.method if update and config.request.update else config.request.method
    )
    template = (
        config.request.update.path if update and config.request.update else config.request.path
    )
    url = config.request.base_url + _path(template, publication, remote_id)
    body, content_type = _body(config, publication, publication_context(publication, remote_id))
    if len(body) > MAX_BODY_BYTES:
        raise PublishError("payload_too_large")
    key = idempotency_key(connector_id, publication, mode)
    headers = {"Content-Type": content_type, **config.request.headers}
    if config.idempotency_header:
        headers[config.idempotency_header] = key
    url, sensitive = authenticate(config, headers, url, body, secrets, oauth_token, now)
    return PreparedRequest(method, url, headers, body, mode, key, sensitive)


def authenticate(
    config: HttpGenericConfig,
    headers: dict[str, str],
    url: str,
    body: bytes,
    secrets: Mapping[str, str] | None,
    oauth_token: str | None,
    now: float | None,
) -> tuple[str, tuple[str, ...]]:
    auth = config.auth
    dry = secrets is None

    def secret(slot: str) -> str:
        if dry:
            return MASK
        value = (secrets or {}).get(slot)
        if not value:
            raise PublishError(f"missing_secret:{slot}")
        return value

    sensitive: list[str] = []
    match auth.type:
        case "api_key":
            key = secret("credential")
            sensitive.append(key)
            if auth.key_location == "header":
                headers[auth.key_name] = key
            else:
                url = f"{url}?{urlencode({auth.key_name: key})}"
        case "bearer":
            value = secret("credential")
            sensitive.append(value)
            headers["Authorization"] = f"Bearer {value}"
        case "basic":
            user, password = secret("username"), secret("password")
            sensitive.append(password)
            if dry:
                headers["Authorization"] = f"Basic {MASK}"
            else:
                pair = base64.b64encode(f"{user}:{password}".encode()).decode()
                sensitive.append(pair)
                headers["Authorization"] = f"Basic {pair}"
        case "oauth2_client_credentials":
            token = MASK if dry else oauth_token
            if not token:
                raise PublishError("oauth_token_missing")
            sensitive.append(token)
            headers["Authorization"] = f"Bearer {token}"
        case "hmac":
            _sign(config, headers, body, None if dry else secret("signing_key"), now)
            if not dry:
                sensitive.append(secret("signing_key"))
        case "mtls" | "none":
            pass  # mTLS authenticates at the TLS layer (client certificate)
    return url, tuple(sensitive)


def _sign(
    config: HttpGenericConfig,
    headers: dict[str, str],
    body: bytes,
    key: str | None,
    now: float | None,
) -> None:
    """HMAC of the body (of ``timestamp.body`` with a timestamp header); masked dry-run."""
    auth = config.auth
    stamp = str(int(now if now is not None else time.time()))
    if auth.timestamp_header:
        headers[auth.timestamp_header] = stamp
    if key is None:
        headers[auth.signed_header] = f"{auth.digest_prefix}{MASK}"
        return
    signed = f"{stamp}.".encode() + body if auth.timestamp_header else body
    digest = hmac.new(key.encode(), signed, auth.algorithm).digest()
    encoded = digest.hex() if auth.encoding == "hex" else base64.b64encode(digest).decode()
    headers[auth.signed_header] = f"{auth.digest_prefix}{encoded}"
