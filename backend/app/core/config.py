"""Application settings, read from environment variables prefixed with ``VV_``.

Secrets are typed ``SecretStr`` so they never appear in ``repr`` or logs.
There are no default credentials: a missing secret fails at startup.
"""

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Audience = Literal["backoffice", "portal"]
Environment = Literal["dev", "test", "prod"]


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

    backoffice_origin: AnyHttpUrl = AnyHttpUrl("https://backoffice.localhost")
    portal_origin: AnyHttpUrl = AnyHttpUrl("https://portal.localhost")

    max_request_body_bytes: int = Field(default=1_048_576, ge=1024, le=50 * 1_048_576)

    scheduler_tick_seconds: float = Field(default=15.0, ge=1.0, le=3600.0)

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"

    def database_url_for(self, audience: Audience) -> str:
        """DSN of the least-privileged role serving the given API audience."""
        url = self.database_url_portal if audience == "portal" else self.database_url_app
        return url.get_secret_value()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # values come from the environment
