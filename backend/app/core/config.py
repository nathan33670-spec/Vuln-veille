"""Application settings, read from environment variables prefixed with ``VV_``.

Secrets are typed ``SecretStr`` so they never appear in ``repr`` or logs.
There are no default credentials: a missing secret fails at startup.
"""

import base64
import binascii
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Audience = Literal["backoffice", "portal"]
Environment = Literal["dev", "test", "prod"]
PasswordHashProfile = Literal["strong", "fast-insecure-tests-only"]

MIN_SECRET_KEY_BYTES = 32
AES_KEY_BYTES = 32


def _decode_key(value: SecretStr, name: str) -> bytes:
    try:
        raw = base64.b64decode(value.get_secret_value(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} must be base64") from exc
    if len(raw) != AES_KEY_BYTES:
        raise ValueError(f"{name} must decode to {AES_KEY_BYTES} bytes")
    return raw


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VV_", extra="ignore", frozen=True)

    environment: Environment = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # One PostgreSQL role per component (see SECURITY.md §4.10).
    database_url_app: SecretStr
    database_url_portal: SecretStr
    database_url_worker: SecretStr
    database_url_migrator: SecretStr

    redis_url: SecretStr

    # HMAC key for CSRF tokens, one-time tokens and recovery codes (>= 32 bytes).
    secret_key: SecretStr
    # AES-256-GCM key encrypting TOTP secrets at rest (base64, 32 bytes).
    kek_totp: SecretStr

    # Secret vault (ADR-013). Public keys ("<id>:<base64>") let a component seal secrets;
    # private keyrings are files "<purpose>.keyring" in this directory (Docker secrets),
    # mounted only into the components that use that purpose.
    vault_public_key_llm: str | None = None
    vault_public_key_source: str | None = None
    vault_public_key_connector: str | None = None
    vault_public_key_webhook: str | None = None
    vault_keyring_dir: Path | None = None

    # Egress proxy (smokescreen) for every outbound request of the workers (ADR-012).
    # Mandatory in production; without it, development connects directly (IP pinned).
    egress_proxy_url: str | None = None

    backoffice_origin: AnyHttpUrl = AnyHttpUrl("https://backoffice.localhost")
    portal_origin: AnyHttpUrl = AnyHttpUrl("https://portal.localhost")

    max_request_body_bytes: int = Field(default=1_048_576, ge=1024, le=50 * 1_048_576)
    scheduler_tick_seconds: float = Field(default=15.0, ge=1.0, le=3600.0)

    # Sessions (SECURITY.md §4.2).
    backoffice_session_idle_minutes: int = Field(default=30, ge=5, le=24 * 60)
    backoffice_session_absolute_hours: int = Field(default=12, ge=1, le=7 * 24)
    portal_session_idle_minutes: int = Field(default=120, ge=5, le=24 * 60)
    portal_session_absolute_hours: int = Field(default=7 * 24, ge=1, le=30 * 24)
    pending_mfa_minutes: int = Field(default=5, ge=1, le=30)
    step_up_minutes: int = Field(default=10, ge=1, le=60)

    invitation_ttl_hours: int = Field(default=24, ge=1, le=7 * 24)
    password_reset_ttl_minutes: int = Field(default=30, ge=5, le=24 * 60)

    password_hash_profile: PasswordHashProfile = "strong"  # noqa: S105 - not a password

    # Outgoing e-mail. Without a host, messages are only logged (development).
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True
    smtp_from: str = "Vuln-Veille <no-reply@localhost>"

    @field_validator("secret_key")
    @classmethod
    def _secret_key_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode()) < MIN_SECRET_KEY_BYTES:
            raise ValueError(f"secret_key must be at least {MIN_SECRET_KEY_BYTES} bytes")
        return value

    @field_validator("kek_totp")
    @classmethod
    def _kek_is_aes_key(cls, value: SecretStr) -> SecretStr:
        _decode_key(value, "kek_totp")
        return value

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"

    @property
    def secret_key_bytes(self) -> bytes:
        return self.secret_key.get_secret_value().encode()

    @property
    def kek_totp_bytes(self) -> bytes:
        return _decode_key(self.kek_totp, "kek_totp")

    def database_url_for(self, audience: Audience) -> str:
        """DSN of the least-privileged role serving the given API audience."""
        url = self.database_url_portal if audience == "portal" else self.database_url_app
        return url.get_secret_value()

    def origin_for(self, audience: Audience) -> str:
        origin = self.portal_origin if audience == "portal" else self.backoffice_origin
        return str(origin).rstrip("/")

    def session_lifetimes(self, audience: Audience) -> tuple[timedelta, timedelta]:
        """(idle timeout, absolute lifetime) for a fully authenticated session."""
        if audience == "portal":
            return (
                timedelta(minutes=self.portal_session_idle_minutes),
                timedelta(hours=self.portal_session_absolute_hours),
            )
        return (
            timedelta(minutes=self.backoffice_session_idle_minutes),
            timedelta(hours=self.backoffice_session_absolute_hours),
        )

    def model_post_init(self, __context: object) -> None:
        if self.is_prod and self.password_hash_profile != "strong":  # noqa: S105
            raise ValueError("weak password hashing is forbidden in production")
        if self.egress_proxy_url is not None and not self.egress_proxy_url.startswith(
            ("http://", "https://")
        ):
            raise ValueError("egress_proxy_url must be an http(s) URL")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # values come from the environment
