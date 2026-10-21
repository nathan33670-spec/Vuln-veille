"""Connector framework: types, registry and the runtime context of a connector.

A connector type is code (this package); a connector is its configuration, managed
from the interface. Registration enforces the non-negotiable rules at import time:
- no paid type (ADR-023): ``cost_class`` must be free, free_account or ai_billed;
- no credential in the configuration: secrets go through declared slots (vault);
- every contacted domain is declared (it feeds the egress proxy allow-list).
"""

import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from app.net.safe_http import SafeHttpClient
from app.vault.keys import SecretPurpose


class Family(StrEnum):
    SOURCE = "source"
    AI_ENGINE = "ai_engine"
    PUBLISH = "publish"


class Scope(StrEnum):
    GLOBAL = "global"
    WORKSPACE = "workspace"


class CostClass(StrEnum):
    FREE = "free"  # no account at all
    FREE_ACCOUNT = "free_account"  # free key or account
    AI_BILLED = "ai_billed"  # billed on the existing AI subscription; budget required
    PAID = "paid"  # exists only to be refused (ADR-023)


ALLOWED_COSTS = frozenset({CostClass.FREE, CostClass.FREE_ACCOUNT, CostClass.AI_BILLED})

# Family -> Celery queue of the worker holding that family's keyring, and the vault
# purpose of its secrets (ADR-013).
FAMILY_QUEUE = {Family.SOURCE: "collect", Family.AI_ENGINE: "ai", Family.PUBLISH: "publish"}
FAMILY_PURPOSE = {
    Family.SOURCE: SecretPurpose.SOURCE,
    Family.AI_ENGINE: SecretPurpose.LLM,
    Family.PUBLISH: SecretPurpose.CONNECTOR,
}

_KIND = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_SLOT = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_DOMAIN = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Configuration fields must never carry credentials (CLAUDE.md): they go in slots.
_SECRET_LIKE = re.compile(r"(token|secret|password|passwd|api_?key|credential|private_key)")


class ConnectorConfig(BaseModel):
    """Base of every type's non-secret configuration (also generates the UI form)."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Quotas(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requests_per_minute: int | None = Field(default=None, ge=1, le=10_000)
    requests_per_day: int | None = Field(default=None, ge=1, le=10_000_000)
    requests_per_month: int | None = Field(default=None, ge=1, le=100_000_000)
    max_requests_per_run: int | None = Field(default=None, ge=1, le=100_000)
    monthly_budget_eur: Decimal | None = Field(default=None, ge=0, le=100_000, decimal_places=2)

    @model_validator(mode="after")
    def _consistent(self) -> "Quotas":
        if (
            self.requests_per_day is not None
            and self.requests_per_month is not None
            and self.requests_per_day > self.requests_per_month
        ):
            raise ValueError("requests_per_day cannot exceed requests_per_month")
        return self


@dataclass(frozen=True)
class SecretSlot:
    name: str
    label: str
    required: bool = True


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    # Short, user-facing message written by the type's code; never contains secrets.
    message: str = ""


@dataclass
class ConnectorContext:
    """What a type's code may use: never raw credentials outside ``secrets``."""

    connector_id: uuid.UUID
    workspace_id: uuid.UUID | None
    config: ConnectorConfig
    secrets: Mapping[str, str]
    http: SafeHttpClient
    quotas: "QuotaGuardProtocol | None" = None


class QuotaGuardProtocol(Protocol):
    async def consume(self, cost: int = 1) -> None:
        """Counts requests; raises QuotaExceededError when a window is full."""


class ConnectorType(ABC):
    kind: ClassVar[str]
    family: ClassVar[Family]
    label: ClassVar[str]
    scopes: ClassVar[frozenset[Scope]]
    cost_class: ClassVar[CostClass]
    config_model: ClassVar[type[ConnectorConfig]]
    secret_slots: ClassVar[tuple[SecretSlot, ...]] = ()
    egress_domains: ClassVar[tuple[str, ...]] = ()
    default_quotas: ClassVar[Quotas] = Quotas()
    # Content types expected from the service (empty: any), and the response cap.
    content_types: ClassVar[tuple[str, ...]] = ()
    max_response_bytes: ClassVar[int] = 10 * 1024 * 1024

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        """Domains this connector contacts; types reading user URLs override it."""
        return cls.egress_domains

    # Periodic synchronisation (global catalogue sources). Types that sync declare
    # ``syncs = True``, a ``sync_interval_minutes`` configuration field, and ``sync``.
    syncs: ClassVar[bool] = False

    @abstractmethod
    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        """A side-effect-free call proving the configuration works (one result)."""

    async def sync(self, job: "SyncJob") -> dict[str, int]:
        """One synchronisation run; returns counters for the logs."""
        raise NotImplementedError(self.kind)


Sleep = Callable[[float], Awaitable[None]]


@dataclass
class SyncJob:
    db: "AsyncSession"
    ctx: ConnectorContext
    connector_id: uuid.UUID
    now: datetime
    sleep: Sleep


class RegistrationError(TypeError):
    pass


_REGISTRY: dict[str, type[ConnectorType]] = {}


def _validate(cls: type[ConnectorType]) -> None:
    if not _KIND.fullmatch(getattr(cls, "kind", "")):
        raise RegistrationError(f"{cls.__name__}: invalid kind")
    if cls.cost_class not in ALLOWED_COSTS:
        raise RegistrationError(f"{cls.kind}: paid connector types are forbidden (ADR-023)")
    if not cls.scopes:
        raise RegistrationError(f"{cls.kind}: at least one scope")
    if not issubclass(cls.config_model, ConnectorConfig):
        raise RegistrationError(f"{cls.kind}: config_model must extend ConnectorConfig")
    for name in cls.config_model.model_fields:
        if _SECRET_LIKE.search(name):
            raise RegistrationError(
                f"{cls.kind}: config field {name!r} looks like a credential; use a secret slot"
            )
    for slot in cls.secret_slots:
        if not _SLOT.fullmatch(slot.name):
            raise RegistrationError(f"{cls.kind}: invalid secret slot {slot.name!r}")
    for domain in cls.egress_domains:
        if not _DOMAIN.fullmatch(domain):
            raise RegistrationError(f"{cls.kind}: invalid egress domain {domain!r}")
    if cls.syncs and "sync_interval_minutes" not in cls.config_model.model_fields:
        raise RegistrationError(f"{cls.kind}: synced types need sync_interval_minutes")
    if cls.cost_class == CostClass.AI_BILLED and cls.default_quotas.monthly_budget_eur is None:
        raise RegistrationError(f"{cls.kind}: AI-billed types need a default monthly budget")


def register(cls: type[ConnectorType]) -> type[ConnectorType]:
    _validate(cls)
    if cls.kind in _REGISTRY and _REGISTRY[cls.kind] is not cls:
        raise RegistrationError(f"connector kind {cls.kind!r} registered twice")
    _REGISTRY[cls.kind] = cls
    return cls


def unregister(kind: str) -> None:
    """Tests only."""
    _REGISTRY.pop(kind, None)


def registered() -> Mapping[str, type[ConnectorType]]:
    from app.connectors import types  # noqa: F401, PLC0415 - registers the built-in types

    return dict(_REGISTRY)


def get_type(kind: str) -> type[ConnectorType]:
    types_ = registered()
    if kind not in types_:
        raise KeyError(kind)
    return types_[kind]


def config_schema(cls: type[ConnectorType]) -> dict[str, Any]:
    return cls.config_model.model_json_schema()
