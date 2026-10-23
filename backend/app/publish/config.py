"""Configuration of the generic HTTP publication connector (spec 05 §2-3, ADR-030).

Everything here is non-secret and editable from the interface; credentials go in the
connector's secret slots, required according to the authentication type. Field names
never look like credentials (the connector framework refuses them).
"""

import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.connectors.base import ConnectorConfig
from app.publish.mapping import validate_mapping
from app.workflows.expressions import ExpressionError, compile_expression, compile_template

AuthType = Literal[
    "none", "api_key", "bearer", "basic", "oauth2_client_credentials", "mtls", "hmac"
]
Method = Literal["POST", "PUT", "PATCH"]
BodyFormat = Literal["json", "csaf", "markdown"]

_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_PARAM = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
# Set by the connector itself; static headers cannot override them.
RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
    }
)
_SECRET_LIKE = re.compile(r"(token|secret|password|passwd|api[-_]?key|credential|signature)", re.I)
MAX_HEADERS = 20
RETRYABLE_DEFAULT = (429, 500, 502, 503, 504)

# Secret slots each authentication type needs (others stay optional and unused).
REQUIRED_SLOTS: dict[str, tuple[str, ...]] = {
    "none": (),
    "api_key": ("credential",),
    "bearer": ("credential",),
    "basic": ("username", "password"),
    "oauth2_client_credentials": ("client_id", "client_secret"),
    "mtls": ("client_certificate", "client_key"),
    "hmac": ("signing_key",),
}


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _url(value: str, *, label: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"{label}: http(s) URL with a host required")
    if parts.username or parts.password:
        raise ValueError(f"{label}: no credentials in the URL")
    if parts.query or parts.fragment:
        raise ValueError(f"{label}: no query string or fragment")
    return value.rstrip("/")


def _path(value: str) -> str:
    if not value.startswith("/") or "://" in value or value.startswith("//"):
        raise ValueError("relative path starting with / required")
    try:
        compile_template(value)
    except ExpressionError as exc:
        raise ValueError(str(exc)) from None
    return value


class UpdateRequest(_Part):
    method: Method = "PUT"
    path: str = Field(max_length=500, description="Gabarit Liquid ; {{ remote_id }} disponible")

    @field_validator("path")
    @classmethod
    def _check_path(cls, value: str) -> str:
        return _path(value)


class RequestSpec(_Part):
    base_url: str = Field(
        max_length=500, description="HTTPS ; HTTP seulement sur réseau privé approuvé"
    )
    method: Method = "POST"
    path: str = Field(default="/", max_length=500, description="Gabarit Liquid")
    update: UpdateRequest | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=20, ge=1, le=60)
    health_path: str = Field(default="", max_length=500, description="GET sans effet de bord")

    @field_validator("base_url")
    @classmethod
    def _base(cls, value: str) -> str:
        return _url(value, label="base_url")

    @field_validator("path")
    @classmethod
    def _check_path(cls, value: str) -> str:
        return _path(value)

    @field_validator("health_path")
    @classmethod
    def _health(cls, value: str) -> str:
        return _path(value) if value else value

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > MAX_HEADERS:
            raise ValueError("too many headers")
        for name, header in value.items():
            if not _HEADER.fullmatch(name) or name.lower() in RESERVED_HEADERS:
                raise ValueError(f"header {name!r} not allowed")
            if _SECRET_LIKE.search(name):
                raise ValueError(f"header {name!r} looks like a credential: use authentication")
            if len(header) > 500 or any(c in header for c in "\r\n\0"):  # noqa: PLR2004
                raise ValueError(f"header {name!r}: invalid value")
        return value


class AuthSpec(_Part):
    type: AuthType = "none"
    # api_key: where the key goes.
    key_location: Literal["header", "query"] = "header"
    key_name: str = Field(default="X-API-Key", max_length=64)
    # oauth2_client_credentials
    endpoint_url: str | None = Field(default=None, max_length=500, description="URL du jeton")
    scope: str = Field(default="", max_length=500)
    audience: str = Field(default="", max_length=500)
    # hmac
    algorithm: Literal["sha256", "sha512"] = "sha256"
    signed_header: str = Field(default="X-Signature", max_length=64)
    digest_prefix: str = Field(default="sha256=", max_length=20)
    encoding: Literal["hex", "base64"] = "hex"
    timestamp_header: str = Field(
        default="", max_length=64, description="Signature de « ts.corps »"
    )

    @field_validator("key_name")
    @classmethod
    def _key_name(cls, value: str) -> str:
        if not (_HEADER.fullmatch(value) or _PARAM.fullmatch(value)):
            raise ValueError("invalid name")
        return value

    @field_validator("signed_header", "timestamp_header")
    @classmethod
    def _header_name(cls, value: str) -> str:
        if value and (not _HEADER.fullmatch(value) or value.lower() in RESERVED_HEADERS):
            raise ValueError("invalid header name")
        return value

    @field_validator("endpoint_url")
    @classmethod
    def _endpoint(cls, value: str | None) -> str | None:
        return _url(value, label="endpoint_url") if value else value

    @model_validator(mode="after")
    def _complete(self) -> "AuthSpec":
        if self.type == "oauth2_client_credentials" and not self.endpoint_url:
            raise ValueError("endpoint_url required for oauth2_client_credentials")
        if (
            self.type == "api_key"
            and self.key_location == "header"
            and (not _HEADER.fullmatch(self.key_name) or self.key_name.lower() in RESERVED_HEADERS)
        ):
            raise ValueError("invalid key header")
        return self


class BodySpec(_Part):
    format: BodyFormat = "json"
    mapping: dict[str, Any] | list[Any] | None = None

    @model_validator(mode="after")
    def _mapping(self) -> "BodySpec":
        if self.format == "json":
            if self.mapping is None:
                raise ValueError("mapping required for a JSON body")
            errors = validate_mapping(self.mapping)
            if errors:
                first = errors[0]
                raise ValueError(f"mapping {first['path']}: {first['code']}")
        return self


class ResponseSpec(_Part):
    success_status: list[int] = Field(default_factory=lambda: [200, 201, 202, 204])
    remote_id_path: str = Field(default="", max_length=500, description="JMESPath sur la réponse")

    @field_validator("success_status")
    @classmethod
    def _statuses(cls, value: list[int]) -> list[int]:
        if not value or any(not 200 <= s <= 299 for s in value):  # noqa: PLR2004
            raise ValueError("2xx statuses only")
        return sorted(set(value))

    @field_validator("remote_id_path")
    @classmethod
    def _remote(cls, value: str) -> str:
        if value:
            try:
                compile_expression(value)
            except ExpressionError as exc:
                raise ValueError(str(exc)) from None
        return value


class RetrySpec(_Part):
    max_attempts: int = Field(default=5, ge=1, le=8)
    backoff_seconds: list[int] = Field(default_factory=lambda: [10, 30, 120, 600, 1800])
    retry_on: list[int] = Field(default_factory=lambda: list(RETRYABLE_DEFAULT))
    retry_network: bool = True

    @field_validator("backoff_seconds")
    @classmethod
    def _backoff(cls, value: list[int]) -> list[int]:
        if not value or any(not 1 <= s <= 86_400 for s in value) or len(value) > 8:  # noqa: PLR2004
            raise ValueError("1 to 8 delays between 1 s and 24 h")
        return value

    @field_validator("retry_on")
    @classmethod
    def _retry_on(cls, value: list[int]) -> list[int]:
        if any(s != 429 and not 500 <= s <= 599 for s in value):  # noqa: PLR2004
            raise ValueError("429 and 5xx only")
        return sorted(set(value))


class HttpGenericConfig(ConnectorConfig):
    request: RequestSpec
    auth: AuthSpec = Field(default_factory=AuthSpec)
    body: BodySpec
    response: ResponseSpec = Field(default_factory=ResponseSpec)
    idempotency_header: str = Field(default="Idempotency-Key", max_length=64)
    retry: RetrySpec = Field(default_factory=RetrySpec)
    rate_limit_per_minute: int = Field(default=30, ge=1, le=600)

    @field_validator("idempotency_header")
    @classmethod
    def _idempotency(cls, value: str) -> str:
        if value and (not _HEADER.fullmatch(value) or value.lower() in RESERVED_HEADERS):
            raise ValueError("invalid header name")
        return value

    def hosts(self) -> tuple[str, ...]:
        """Every host the connector contacts (target, token endpoint)."""
        urls = [
            self.request.base_url,
            *([self.auth.endpoint_url] if self.auth.endpoint_url else []),
        ]
        return tuple(dict.fromkeys((urlsplit(u).hostname or "").lower() for u in urls))

    def uses_http(self) -> bool:
        urls = [
            self.request.base_url,
            *([self.auth.endpoint_url] if self.auth.endpoint_url else []),
        ]
        return any(urlsplit(u).scheme == "http" for u in urls)
