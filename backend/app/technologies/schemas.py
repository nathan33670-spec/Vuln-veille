"""Technology API schemas."""

import re
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field

from app.iam.schemas import StrictIn

NAME = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,99}$")
CPE_PREFIX = re.compile(r"^cpe:2\.3:[aho]:[^:\s]+:[^:\s]+(:[^:\s]+)*$")
MAX_ALIAS = 100
PURL = re.compile(r"^pkg:[a-z][a-z0-9.+-]*/[^\s]{1,200}$")


def _normalized(value: str) -> str:
    value = value.strip().lower()
    if not NAME.fullmatch(value):
        raise ValueError("lowercase letters, digits and . _ + - only")
    return value


def _cpes(values: list[str]) -> list[str]:
    cleaned = sorted({v.strip().lower() for v in values})
    if any(not CPE_PREFIX.fullmatch(v) for v in cleaned):
        raise ValueError("CPE 2.3 prefixes, e.g. cpe:2.3:a:apache:log4j")
    return cleaned


def _purls(values: list[str]) -> list[str]:
    cleaned = sorted({v.strip() for v in values})
    if any(not PURL.fullmatch(v) for v in cleaned):
        raise ValueError("package URLs, e.g. pkg:maven/org.apache.logging.log4j/log4j-core")
    return cleaned


def _aliases(values: list[str]) -> list[str]:
    cleaned = sorted({v.strip() for v in values if v.strip()})
    if any(len(v) > MAX_ALIAS for v in cleaned):
        raise ValueError("aliases are at most 100 characters")
    return cleaned


VendorName = Annotated[str, AfterValidator(_normalized)]
Aliases = Annotated[list[str], Field(max_length=50), AfterValidator(_aliases)]
CpePrefixes = Annotated[list[str], Field(max_length=50), AfterValidator(_cpes)]
Purls = Annotated[list[str], Field(max_length=50), AfterValidator(_purls)]


class TechnologyCreate(StrictIn):
    vendor: VendorName
    product: VendorName
    display_name: str = Field(min_length=1, max_length=200)
    aliases: Aliases = Field(default_factory=list)
    cpe_prefixes: CpePrefixes = Field(default_factory=list)
    purls: Purls = Field(default_factory=list)
    category: str = Field(default="", max_length=100)


class TechnologyUpdate(StrictIn):
    version: int
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    aliases: Aliases | None = None
    cpe_prefixes: CpePrefixes | None = None
    purls: Purls | None = None
    category: str | None = Field(default=None, max_length=100)
    status: str | None = Field(default=None, pattern="^(active|deprecated)$")


class TechnologyMerge(StrictIn):
    into: uuid.UUID


class TechnologyOut(BaseModel):
    id: uuid.UUID
    vendor: str
    product: str
    display_name: str
    aliases: list[str]
    cpe_prefixes: list[str]
    purls: list[str]
    category: str
    status: str
    merged_into: uuid.UUID | None
    version: int
    updated_at: datetime


class CpeSuggestionOut(BaseModel):
    vendor: str
    product: str
    cpe_prefix: str
    cve_count: int
    existing_technology_id: uuid.UUID | None
