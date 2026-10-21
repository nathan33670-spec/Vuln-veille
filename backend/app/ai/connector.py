"""Base of the ``ai_engine`` connector types: model catalogue sync and capability
verification, shared by every provider (the provider code is in ``engines/``)."""

import uuid
from abc import abstractmethod
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.capabilities import verify_model
from app.ai.config import EngineConfig
from app.ai.models import AIModel
from app.ai.types import AIEngine, AIError
from app.connectors.base import (
    ConnectorContext,
    ConnectorType,
    CostClass,
    Family,
    HealthResult,
    Scope,
)
from app.connectors.models import Connector
from app.core.narrow import expect

MAX_MODELS_CHECKED = 5


class EngineConnectorType(ConnectorType):
    family = Family.AI_ENGINE
    scopes = frozenset({Scope.GLOBAL, Scope.WORKSPACE})
    cost_class: ClassVar[CostClass]
    config_model: ClassVar[type[EngineConfig]]
    content_types = ("application/json",)
    max_response_bytes = 8 * 1024 * 1024
    read_timeout = 180.0
    total_timeout = 300.0

    @abstractmethod
    def engine(self, ctx: ConnectorContext) -> AIEngine:
        """The provider adapter bound to this connector's configuration and secrets."""

    async def health_check(self, ctx: ConnectorContext) -> HealthResult:
        """Verifies the declared capabilities of each enabled model (spec 07 §4.2)."""
        config = expect(ctx.config, EngineConfig)
        engine = self.engine(ctx)
        results: dict[str, Any] = {}
        for model in [m for m in config.models if m.enabled][:MAX_MODELS_CHECKED]:
            try:
                results[model.model_id] = await verify_model(
                    engine, model.model_id, model.capabilities()
                )
            except AIError as exc:
                results[model.model_id] = {"ok": False, "error": exc.code}
        ok = bool(results) and all(r.get("ok") for r in results.values())
        failed = [m for m, r in results.items() if not r.get("ok")]
        message = "capacités vérifiées" if ok else f"échec : {', '.join(failed)[:300]}"
        return HealthResult(ok=ok, message=message, details={"models": results})

    async def on_saved(self, db: AsyncSession, connector: Connector) -> None:
        """Mirrors the declared models into the catalogue (app role, connector scope)."""
        config = self.config_model.model_validate(connector.config)
        rows = {
            m.model_id: m
            for m in (
                await db.execute(select(AIModel).where(AIModel.connector_id == connector.id))
            ).scalars()
        }
        for model in config.models:
            row = rows.pop(model.model_id, None)
            if row is None:
                row = AIModel(
                    id=uuid.uuid4(),
                    connector_id=connector.id,
                    model_id=model.model_id,
                    workspace_id=connector.workspace_id,
                    checks={},
                )
                db.add(row)
            elif row.declared != model.capabilities().as_dict():
                row.verified, row.verified_at, row.checks = None, None, {}
            row.connector_kind, row.connector_name = connector.kind, connector.name
            row.connector_enabled = connector.enabled
            row.display_name = model.display_name or model.model_id
            row.enabled = model.enabled
            row.declared = model.capabilities().as_dict()
            row.data_classes = list(config.data_classes)
            row.location = config.location
            row.price_input_per_mtok = model.price_input_per_mtok
            row.price_output_per_mtok = model.price_output_per_mtok
        if rows:
            await db.execute(delete(AIModel).where(AIModel.id.in_([r.id for r in rows.values()])))
        await db.flush()

    async def on_checked(
        self, db: AsyncSession, connector: Connector, result: HealthResult, now: datetime
    ) -> None:
        """Stores the verified capabilities (worker role)."""
        models = (result.details or {}).get("models", {})
        rows = (
            await db.execute(select(AIModel).where(AIModel.connector_id == connector.id))
        ).scalars()
        for row in rows:
            outcome = models.get(row.model_id)
            if outcome is None:
                continue
            row.checks = outcome
            row.verified = outcome.get("verified")
            row.verified_at = now
