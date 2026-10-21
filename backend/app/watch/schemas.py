"""Watch API schemas."""

import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, HttpUrl, field_validator

from app.iam.schemas import StrictIn

CWE = re.compile(r"^CWE-\d{1,6}$")


def _terms(values: list[str]) -> list[str]:
    cleaned = sorted({v.strip() for v in values if v.strip()})
    if any(len(v) > 100 for v in cleaned):  # noqa: PLR2004
        raise ValueError("at most 100 characters per term")
    return cleaned


def _cwes(values: list[str]) -> list[str]:
    cleaned = sorted({v.strip().upper() for v in values})
    if any(not CWE.fullmatch(v) for v in cleaned):
        raise ValueError("CWE identifiers, e.g. CWE-79")
    return cleaned


Terms = Annotated[list[str], Field(max_length=200), AfterValidator(_terms)]
Cwes = Annotated[list[str], Field(max_length=200), AfterValidator(_cwes)]


class WatchScopeIn(StrictIn):
    version: int = Field(description="0 when the scope was never saved.")
    mode: Literal["all", "scoped"] = "scoped"
    technology_ids: Annotated[list[uuid.UUID], Field(max_length=2000)] = Field(default_factory=list)
    vendors: Terms = Field(default_factory=list)
    keywords: Terms = Field(default_factory=list)
    cvss_min: Decimal | None = Field(default=None, ge=0, le=10, decimal_places=1)
    include_unscored: Literal["include", "wait", "exclude"] = "wait"
    always_include_kev: bool = True
    cwe_include: Cwes = Field(default_factory=list)
    cwe_exclude: Cwes = Field(default_factory=list)


class WatchScopeOut(BaseModel):
    mode: str
    technology_ids: list[uuid.UUID]
    vendors: list[str]
    keywords: list[str]
    cvss_min: Decimal | None
    include_unscored: str
    always_include_kev: bool
    cwe_include: list[str]
    cwe_exclude: list[str]
    version: int
    updated_at: datetime | None


class ScopePreviewItem(BaseModel):
    cve_id: str
    published_at: datetime | None
    severity: str | None
    base_score: Decimal | None
    decision: str
    reasons: list[str]


class ScopePreviewOut(BaseModel):
    days: int
    total: int
    in_scope: int
    pending: int
    out_of_scope: int
    items: list[ScopePreviewItem]


# Followed sources: the configuration is validated per type (no free-form URLs to
# internal hosts: every fetch still goes through the connectors and SafeHttpClient).
class _HttpsUrl(BaseModel):
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def _https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError("https only")
        return value


class RssConfig(_HttpsUrl):
    type: Literal["rss"] = "rss"


class WebsiteConfig(_HttpsUrl):
    type: Literal["website"] = "website"


class XAccountConfig(BaseModel):
    type: Literal["x_account"] = "x_account"
    handle: str = Field(pattern=r"^[A-Za-z0-9_]{1,15}$")


class GithubRepoConfig(BaseModel):
    type: Literal["github_repo"] = "github_repo"
    repo: str = Field(pattern=r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")


class MastodonAccountConfig(BaseModel):
    type: Literal["mastodon_account"] = "mastodon_account"
    account: str = Field(pattern=r"^[A-Za-z0-9_]{1,30}@[a-z0-9.-]{3,253}\.[a-z]{2,63}$")


class BlueskyAccountConfig(BaseModel):
    type: Literal["bluesky_account"] = "bluesky_account"
    handle: str = Field(pattern=r"^[a-z0-9.-]{3,253}\.[a-z]{2,63}$")


class SubredditConfig(BaseModel):
    type: Literal["subreddit"] = "subreddit"
    name: str = Field(pattern=r"^[A-Za-z0-9_]{2,21}$")


SourceConfig = Annotated[
    RssConfig
    | WebsiteConfig
    | XAccountConfig
    | GithubRepoConfig
    | MastodonAccountConfig
    | BlueskyAccountConfig
    | SubredditConfig,
    Field(discriminator="type"),
]
Tags = Annotated[list[str], Field(max_length=30), AfterValidator(_terms)]


class WatchSourceCreate(StrictIn):
    name: str = Field(min_length=1, max_length=100)
    config: SourceConfig
    tags: Tags = Field(default_factory=list)
    trust_level: Literal["low", "medium", "high"] = "medium"
    enabled: bool = True


class WatchSourceUpdate(StrictIn):
    version: int
    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: SourceConfig | None = None
    tags: Tags | None = None
    trust_level: Literal["low", "medium", "high"] | None = None
    enabled: bool | None = None


class WatchSourceOut(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    config: dict[str, object]
    tags: list[str]
    trust_level: str
    enabled: bool
    version: int
    updated_at: datetime
