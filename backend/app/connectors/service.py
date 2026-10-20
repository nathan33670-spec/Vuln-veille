"""Connector management (API side): validation, persistence, health state.

Secrets are referenced, never stored here: a connector may only reference secrets of
its own scope (the same workspace, or global for a global connector) whose purpose is
its family's (ADR-013), so a CERT connector can never point at a VOC secret.
"""

import uuid
from typing import Any, Literal

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import (
    FAMILY_PURPOSE,
    ConnectorConfig,
    ConnectorType,
    CostClass,
    Family,
    Quotas,
    Scope,
    get_type,
)
from app.connectors.models import Connector
from app.core.errors import ApiError
from app.vault.models import Secret

FAILING_AFTER = 3
Health = Literal["unknown", "ok", "degraded", "failing"]


def _invalid(code: str, error: ValidationError | None = None) -> ApiError:
    # Field locations and error types only: submitted values are never echoed.
    errors = [{"loc": list(e["loc"]), "type": e["type"]} for e in error.errors()] if error else None
    return ApiError(422, code, errors)


def connector_type(kind: str, family: Family, scope: Scope) -> type[ConnectorType]:
    try:
        type_ = get_type(kind)
    except KeyError:
        raise _invalid("unknown_kind") from None
    if type_.family != family:
        raise _invalid("wrong_family")
    if scope not in type_.scopes:
        raise _invalid("scope_not_allowed")
    return type_


def validate_config(type_: type[ConnectorType], raw: dict[str, Any]) -> ConnectorConfig:
    try:
        return type_.config_model.model_validate(raw)
    except ValidationError as exc:
        raise _invalid("invalid_config", exc) from None


def validate_quotas(type_: type[ConnectorType], raw: dict[str, Any] | None) -> Quotas:
    try:
        quotas = type_.default_quotas if raw is None else Quotas.model_validate(raw)
    except ValidationError as exc:
        raise _invalid("invalid_quotas", exc) from None
    if type_.cost_class == CostClass.AI_BILLED and quotas.monthly_budget_eur is None:
        raise _invalid("budget_required")
    return quotas


async def validate_secret_refs(
    db: AsyncSession,
    type_: type[ConnectorType],
    refs: dict[str, uuid.UUID],
    workspace_id: uuid.UUID | None,
) -> dict[str, str]:
    slots = {slot.name: slot for slot in type_.secret_slots}
    unknown = set(refs) - set(slots)
    if unknown:
        raise _invalid("unknown_secret_slot")
    if any(slot.required and name not in refs for name, slot in slots.items()):
        raise _invalid("missing_secret")
    purpose = FAMILY_PURPOSE[type_.family]
    for secret_id in refs.values():
        secret = await db.get(Secret, secret_id)
        if secret is None or secret.workspace_id != workspace_id:
            raise _invalid("secret_not_found")
        if secret.purpose != purpose:
            raise _invalid("secret_purpose_mismatch")
    return {name: str(secret_id) for name, secret_id in refs.items()}


def health_of(connector: Connector) -> Health:
    if connector.last_check_at is None:
        return "unknown"
    if connector.consecutive_failures == 0:
        return "ok"
    return "failing" if connector.consecutive_failures >= FAILING_AFTER else "degraded"


async def get_connector(
    db: AsyncSession, connector_id: uuid.UUID, workspace_id: uuid.UUID | None, family: Family
) -> Connector:
    connector = await db.get(Connector, connector_id)
    if connector is None or connector.workspace_id != workspace_id or connector.family != family:
        raise HTTPException(status_code=404, detail="not_found")
    return connector


async def list_connectors(
    db: AsyncSession, workspace_id: uuid.UUID | None, family: Family
) -> list[Connector]:
    query = select(Connector).where(Connector.family == family).order_by(Connector.name)
    query = (
        query.where(Connector.workspace_id.is_(None))
        if workspace_id is None
        else query.where(Connector.workspace_id == workspace_id)
    )
    return list((await db.execute(query)).scalars())


async def flush_unique(db: AsyncSession) -> None:
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="name_taken") from exc


async def secret_in_use(db: AsyncSession, secret_id: uuid.UUID) -> bool:
    """Whether a visible connector references the secret (in-scope by construction)."""
    found = await db.execute(
        text(
            "SELECT 1 FROM connectors c, jsonb_each_text(c.secret_refs) ref "
            "WHERE ref.value = :id LIMIT 1"
        ),
        {"id": str(secret_id)},
    )
    return found.first() is not None
