"""Control and notification nodes (spec 02 §7)."""

from typing import Any, ClassVar, Literal

from pydantic import Field

from app.workflows.base import (
    NodeCategory,
    NodeContext,
    NodeParams,
    NodeType,
    Outputs,
    expect,
    register_node,
)
from app.workflows.expressions import Expr, Tpl

MAX_LISTED = 50
DEFAULT_SUBJECT = "[Vuln-Veille] {{ count }} élément(s) : {{ workflow }}"
DEFAULT_BODY = """Le workflow « {{ workflow }} » signale {{ count }} élément(s) :
{% for i in items %}
- {{ i.ref | default: i.cve_id | default: i.title }}
  {%- if i.severity %} ({{ i.severity }}{% if i.kev %}, KEV{% endif %}){% endif %}
  {%- if i.title and i.ref %} : {{ i.title | truncate: 150 }}{% endif %}
{%- endfor %}
"""


class IfParams(NodeParams):
    condition: Expr


@register_node
class If(NodeType):
    type = "control.if"
    label = "Condition"
    category = NodeCategory.CONTROL
    Params = IfParams
    outputs: ClassVar[tuple[str, ...]] = ("true", "false")

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, IfParams)
        result: Outputs = {"true": [], "false": []}
        for entry in inputs.get("in", []):
            port = "true" if params.condition.truthy(ctx.expression_context(entry)) else "false"
            result[port].append(entry)
        return result


class ApprovalParams(NodeParams):
    instructions: str = Field(default="", max_length=1000)


@register_node
class Approval(NodeType):
    """Pauses the run until an analyst decides (handled by the orchestrator)."""

    type = "control.approval"
    label = "Validation humaine"
    category = NodeCategory.CONTROL
    Params = ApprovalParams
    outputs: ClassVar[tuple[str, ...]] = ("approved", "rejected")
    waits_for_approval: ClassVar[bool] = True

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        # Only reached by "test this node": a test never waits, it shows the approved path.
        return {"approved": inputs.get("in", []), "rejected": []}


class EmailParams(NodeParams):
    recipients: Literal["analysts"] = "analysts"
    subject: Tpl = Field(default_factory=lambda: Tpl.model_validate({"$tpl": DEFAULT_SUBJECT}))
    body: Tpl = Field(default_factory=lambda: Tpl.model_validate({"$tpl": DEFAULT_BODY}))


@register_node
class Email(NodeType):
    type = "notify.email"
    label = "E-mail aux analystes"
    category = NodeCategory.OUTPUT
    Params = EmailParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, EmailParams)
        entries = inputs.get("in", [])
        context: dict[str, Any] = {
            **ctx.expression_context(),
            "items": [e.get("json", {}) for e in entries[:MAX_LISTED]],
            "count": len(entries),
            "workflow": ctx.run.workflow_name,
        }
        subject = " ".join(params.subject.render(context).split())[:200]
        body = params.body.render(context)[:50_000]
        recipients = await ctx.repo.analyst_emails()
        if not ctx.dry_run:
            ctx.mails.extend((to, subject, body) for to in recipients)
        ctx.log("email", recipients=len(recipients), dry_run=ctx.dry_run)
        return {"out": entries}
