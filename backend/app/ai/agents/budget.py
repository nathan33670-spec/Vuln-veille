"""Token and cost accounting, monthly budgets per workspace (spec 03 §8).

The cost is an estimate from the model's declared prices (the AI subscription is the
only paid item allowed, ADR-023): input tokens, cache writes at 125 % and cache reads
at 10 % of the input price, output tokens at the output price. A free-tier engine
declares no price and costs 0. With a hard stop, engine calls are refused once the
month's spend reaches the workspace limit; alerts fire once at 50, 80 and 100 %.
"""

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.models import LlmBudget, LlmSpend
from app.ai.models import AIModel
from app.ai.types import Usage

THRESHOLDS = (50, 80, 100)
MILLION = Decimal(1_000_000)


def period_of(now: datetime) -> date:
    return date(now.year, now.month, 1)


def estimate_cost(model: AIModel, usage: Usage) -> Decimal:
    price_in = model.price_input_per_mtok or Decimal(0)
    price_out = model.price_output_per_mtok or Decimal(0)
    weighted_input = (
        Decimal(usage.input_tokens)
        + Decimal(usage.cache_write_tokens) * Decimal("1.25")
        + Decimal(usage.cache_read_tokens) * Decimal("0.1")
    )
    cost = (weighted_input * price_in + Decimal(usage.output_tokens) * price_out) / MILLION
    return cost.quantize(Decimal("0.000001"))


@dataclass(frozen=True)
class BudgetState:
    limit_usd: Decimal | None
    spent_usd: Decimal
    hard_stop: bool

    @property
    def exhausted(self) -> bool:
        return self.hard_stop and self.limit_usd is not None and self.spent_usd >= self.limit_usd

    @property
    def percent(self) -> int | None:
        if not self.limit_usd:
            return None
        return int(self.spent_usd * 100 / self.limit_usd)


async def state(db: AsyncSession, workspace_id: uuid.UUID, now: datetime) -> BudgetState:
    budget = await db.get(LlmBudget, workspace_id)
    spent = (
        await db.execute(
            select(LlmSpend.spent_usd).where(
                LlmSpend.workspace_id == workspace_id, LlmSpend.period == period_of(now)
            )
        )
    ).scalar_one_or_none()
    return BudgetState(
        limit_usd=budget.monthly_limit_usd if budget else None,
        spent_usd=spent or Decimal(0),
        hard_stop=budget.hard_stop if budget else True,
    )


async def charge(
    db: AsyncSession, workspace_id: uuid.UUID, now: datetime, cost: Decimal, usage: Usage
) -> list[int]:
    """Adds one engine call to the month's spend; returns the thresholds just crossed."""
    period = period_of(now)
    values = insert(LlmSpend).values(
        workspace_id=workspace_id,
        period=period,
        spent_usd=cost,
        input_tokens=usage.input_tokens + usage.cache_read_tokens + usage.cache_write_tokens,
        output_tokens=usage.output_tokens,
        calls=1,
        alerts_sent=[],
    )
    excluded = values.excluded
    statement = values.on_conflict_do_update(
        index_elements=[LlmSpend.workspace_id, LlmSpend.period],
        set_={
            "spent_usd": LlmSpend.spent_usd + excluded.spent_usd,
            "input_tokens": LlmSpend.input_tokens + excluded.input_tokens,
            "output_tokens": LlmSpend.output_tokens + excluded.output_tokens,
            "calls": LlmSpend.calls + 1,
            "updated_at": now,
        },
    ).returning(LlmSpend.spent_usd, LlmSpend.alerts_sent)
    spent, sent = (await db.execute(statement)).one()
    budget = await db.get(LlmBudget, workspace_id)
    if budget is None or not budget.monthly_limit_usd:
        return []
    percent = spent * 100 / budget.monthly_limit_usd
    crossed = [t for t in THRESHOLDS if percent >= t and t not in sent]
    if crossed:
        await db.execute(
            update(LlmSpend)
            .where(LlmSpend.workspace_id == workspace_id, LlmSpend.period == period)
            .values(alerts_sent=sorted({*sent, *crossed}))
        )
    return crossed
