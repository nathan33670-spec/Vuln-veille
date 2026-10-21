"""Trigger nodes (spec 02 §6). The firing trigger emits the run's payload as one item;
the dispatcher (``app.workflows.triggers``) decides whether an event starts a run."""

from datetime import UTC, datetime
from itertools import pairwise
from typing import Any, ClassVar, Literal, get_args
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter
from pydantic import Field, field_validator

from app.workflows.base import (
    NodeCategory,
    NodeContext,
    NodeParams,
    NodeType,
    Outputs,
    expect,
    item,
    register_node,
)
from app.workflows.expressions import Expr

MIN_SCHEDULE_MINUTES = 5
CveChange = Literal[
    "cvss_added", "severity_raised", "cpe_added", "kev_added", "exploit_reference_added", "rejected"
]
CVE_CHANGE_TYPES: tuple[CveChange, ...] = get_args(CveChange)


class TriggerNode(NodeType):
    category = NodeCategory.TRIGGER
    inputs: ClassVar[tuple[str, ...]] = ()

    def accepts(self, params: NodeParams, payload: dict[str, Any]) -> bool:
        """Whether an event with this payload starts a run."""
        return True

    def config(self, params: NodeParams) -> dict[str, Any]:
        """Stored on ``workflow_triggers`` when the version is activated."""
        return {}

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        return {"out": [item(ctx.run.trigger_payload, source=f"trigger.{ctx.run.trigger_type}")]}


def _filter_accepts(condition: Expr | None, payload: dict[str, Any]) -> bool:
    return condition is None or condition.truthy({"json": payload, "meta": {}})


class ManualParams(NodeParams):
    pass


@register_node
class ManualTrigger(TriggerNode):
    type = "trigger.manual"
    label = "Lancement manuel"
    trigger_type = "manual"
    Params = ManualParams


class ScheduleParams(NodeParams):
    cron: str = Field(min_length=9, max_length=100, description="Expression cron à 5 champs")
    timezone: str = Field(default="Europe/Paris", max_length=64)

    @field_validator("timezone")
    @classmethod
    def _zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("unknown time zone") from None
        return value

    @field_validator("cron")
    @classmethod
    def _cron(cls, value: str) -> str:
        if len(value.split()) != 5 or not croniter.is_valid(value):  # noqa: PLR2004
            raise ValueError("invalid cron expression")
        start = datetime(2026, 1, 5, tzinfo=UTC)
        times = croniter(value, start)
        fires = [times.get_next(datetime) for _ in range(50)]
        if min(b - a for a, b in pairwise(fires)).total_seconds() < MIN_SCHEDULE_MINUTES * 60:
            raise ValueError(f"at most one run every {MIN_SCHEDULE_MINUTES} minutes")
        return value


def next_fire(cron: str, timezone: str, after: datetime) -> datetime:
    zone = ZoneInfo(timezone)
    local: datetime = croniter(cron, after.astimezone(zone)).get_next(datetime)
    return local.astimezone(UTC)


@register_node
class ScheduleTrigger(TriggerNode):
    type = "trigger.schedule"
    label = "Planification (cron)"
    trigger_type = "schedule"
    Params = ScheduleParams

    def config(self, params: NodeParams) -> dict[str, Any]:
        params = expect(params, ScheduleParams)
        return {"cron": params.cron, "timezone": params.timezone}


class CvePublishedParams(NodeParams):
    filter: Expr | None = Field(
        default=None,
        description="Condition JMESPath sur l'événement, par ex. json.severity == 'CRITICAL'",
    )


@register_node
class CvePublishedTrigger(TriggerNode):
    type = "trigger.cve_published"
    label = "Nouvelle CVE (NVD)"
    trigger_type = "cve_published"
    Params = CvePublishedParams

    def accepts(self, params: NodeParams, payload: dict[str, Any]) -> bool:
        params = expect(params, CvePublishedParams)
        return _filter_accepts(params.filter, payload)


class CveUpdatedParams(NodeParams):
    change_types: list[CveChange] = Field(
        default=list(CVE_CHANGE_TYPES), min_length=1, max_length=6
    )
    filter: Expr | None = None


@register_node
class CveUpdatedTrigger(TriggerNode):
    type = "trigger.cve_updated"
    label = "CVE modifiée (NVD)"
    trigger_type = "cve_updated"
    Params = CveUpdatedParams

    def accepts(self, params: NodeParams, payload: dict[str, Any]) -> bool:
        params = expect(params, CveUpdatedParams)
        changes = set(payload.get("change_types") or [])
        return bool(changes & set(params.change_types)) and _filter_accepts(params.filter, payload)


class WebhookParams(NodeParams):
    pass


@register_node
class WebhookTrigger(TriggerNode):
    """URL unique per trigger; HMAC-SHA256 signature, timestamp and replay checks
    (``app.workflows.webhooks``). The JSON body becomes the run's payload."""

    type = "trigger.webhook"
    label = "Webhook entrant (signé)"
    trigger_type = "webhook"
    Params = WebhookParams


class EventParams(NodeParams):
    event_type: Literal["vuln.created"] = "vuln.created"
    filter: Expr | None = None


@register_node
class EventTrigger(TriggerNode):
    type = "trigger.event"
    label = "Événement de l'espace"
    trigger_type = "event"
    Params = EventParams

    def accepts(self, params: NodeParams, payload: dict[str, Any]) -> bool:
        params = expect(params, EventParams)
        return _filter_accepts(params.filter, payload)

    def config(self, params: NodeParams) -> dict[str, Any]:
        params = expect(params, EventParams)
        return {"event_type": params.event_type}
