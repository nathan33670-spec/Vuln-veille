"""Publication node (spec 02 §7, spec 05 §5, plan 7.8): push validated bulletins.

``publish.api`` queues a push of each item's bulletin to a publication connector; the
``publish`` worker sends it and journals every attempt. The graph is refused unless
every path to this node crosses a ``control.approval`` (ADR-019), and only an
approved or published bulletin is ever pushed. In a node test nothing is queued: the
item carries the request that would be sent, credentials masked.
"""

import uuid
from typing import ClassVar

from pydantic import Field

from app.iam.permissions import Permission
from app.publish.config import HttpGenericConfig
from app.publish.context import PublishError, load_publication
from app.publish.request import build_request
from app.publish.runner import push_task
from app.publish.service import push_target, queue_push
from app.workflows.base import (
    NodeCategory,
    NodeContext,
    NodeParams,
    NodeType,
    Outputs,
    Reference,
    ReferenceField,
    expect,
    register_node,
)
from app.workflows.expressions import Expr


class PublishApiParams(NodeParams):
    connector_id: uuid.UUID = Field(description="Connecteur de publication (espace ou global)")
    bulletin_id: Expr = Field(
        default_factory=lambda: Expr.model_validate({"$expr": "json.bulletin.id"}),
        description="Identifiant du bulletin dans l'élément",
    )
    max_items: int = Field(default=10, ge=1, le=50, description="Envois au maximum par exécution")


@register_node
class PublishApiNode(NodeType):
    type = "publish.api"
    label = "Pousser vers une API (connecteur de publication)"
    category = NodeCategory.OUTPUT
    queue = "publish"
    Params = PublishApiParams
    requires_approval_upstream = True
    required_permissions: ClassVar[frozenset[Permission]] = frozenset(
        {Permission.CONNECTOR_PUBLISH_PUSH}
    )

    def references(self, params: NodeParams) -> list[Reference]:
        connector_id = expect(params, PublishApiParams).connector_id
        return [Reference("connector", connector_id, family="publish")]

    @classmethod
    def reference_fields(cls) -> dict[str, ReferenceField]:
        return {"connector_id": ReferenceField("connector", family="publish")}

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, PublishApiParams)
        db = ctx.repo.db
        entries = inputs.get("in", [])
        if len(entries) > params.max_items:
            ctx.log("items_capped", received=len(entries), processed=params.max_items)
        out = []
        for entry in entries[: params.max_items]:
            data = entry.get("json", {})
            try:
                raw = params.bulletin_id.evaluate(ctx.expression_context(entry))
                bulletin_id = uuid.UUID(str(raw))
                connector = await push_target(db, ctx.workspace_id, params.connector_id)
                publication = await load_publication(db, ctx.workspace_id, bulletin_id)
                if ctx.dry_run:
                    config = HttpGenericConfig.model_validate(connector.config)
                    prepared = build_request(config, publication, connector_id=str(connector.id))
                    result = {"status": "dry_run", "request": prepared.redacted()}
                else:
                    record = await queue_push(
                        db, ctx.workspace_id, connector, publication,
                        origin="workflow", requested_by=None, now=ctx.now,
                        node_run_id=ctx.node_run_id,
                    )  # fmt: skip
                    name, kwargs, _ = push_task(record)
                    ctx.tasks.append((name, kwargs))
                    result = {"status": "queued", "id": str(record.id)}
                    ctx.log("push_queued", ref=publication.bulletin.ref, connector=connector.name)
            except PublishError as exc:  # before ValueError, its base class
                result = {"status": "failed", "error": exc.code}
                ctx.log("push_refused", error=exc.code)
            except ValueError:  # no bulletin identifier in the item
                result = {"status": "failed", "error": "no_bulletin"}
            out.append({"json": {**data, "publication": result}, "meta": entry.get("meta", {})})
        return {"out": out}
