"""Bulletin nodes (spec 02 §7, spec 04 §3, plan 6.8): a draft per vulnerability.

``bulletin.generate_draft`` applies the template chosen by the workspace's rules (or
the one set on the node), generates the fields with the workspace's AI engine through
the agent runtime, and stores a bulletin in ``draft``: nothing reaches a client before
an analyst approves and publishes it (ADR-019). In a node test, the draft is rolled
back with the node's other database writes.
"""

import uuid
from typing import ClassVar, Literal

from pydantic import Field

from app.bulletins.api import active_candidates
from app.bulletins.facts import vulnerability_facts
from app.bulletins.generation import DraftInput, GenerationError, create_draft
from app.bulletins.models import BulletinSettings, BulletinTemplateVersion
from app.bulletins.selection import select_template
from app.iam.permissions import Permission
from app.workflows.base import (
    NodeCategory,
    NodeContext,
    NodeError,
    NodeParams,
    NodeType,
    Outputs,
    Reference,
    ReferenceField,
    expect,
    register_node,
)


class GenerateDraftParams(NodeParams):
    template_id: uuid.UUID | None = Field(
        default=None, description="Modèle imposé ; sinon choisi par les règles de l'espace"
    )
    language: Literal["fr", "en"] | None = Field(default=None, description="Langue du bulletin")
    extra_instructions: str = Field(default="", max_length=2000)
    max_items: int = Field(default=5, ge=1, le=20, description="Drafts créés au maximum")


@register_node
class GenerateDraftNode(NodeType):
    type = "bulletin.generate_draft"
    label = "Rédiger un draft de bulletin (IA)"
    category = NodeCategory.BULLETIN
    queue = "ai"
    Params = GenerateDraftParams
    required_permissions: ClassVar[frozenset[Permission]] = frozenset(
        {Permission.BULLETIN_DRAFT, Permission.AI_AGENT_RUN}
    )

    def references(self, params: NodeParams) -> list[Reference]:
        template_id = expect(params, GenerateDraftParams).template_id
        return [Reference("bulletin_template", template_id)] if template_id else []

    @classmethod
    def reference_fields(cls) -> dict[str, ReferenceField]:
        return {"template_id": ReferenceField("bulletin_template")}

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, GenerateDraftParams)
        if ctx.agents is None:
            raise NodeError("agents_unavailable")
        db = ctx.repo.db
        candidates = await active_candidates(db, ctx.workspace_id)
        settings = await db.get(BulletinSettings, ctx.workspace_id)
        entries = inputs.get("in", [])
        if len(entries) > params.max_items:
            ctx.log("items_capped", received=len(entries), processed=params.max_items)
        out = []
        for entry in entries[: params.max_items]:
            data = entry.get("json", {})
            raw = data.get("vulnerability_id")
            try:
                vulnerability_id = uuid.UUID(str(raw))
            except ValueError:
                ctx.log("no_vulnerability")
                continue
            facts = await vulnerability_facts(db, ctx.workspace_id, vulnerability_id)
            if facts is None:
                ctx.log("vulnerability_not_found")
                continue
            if params.template_id is not None:
                chosen = next((c for c in candidates if c.template_id == params.template_id), None)
                version_id = chosen.version_id if chosen else None
            else:
                selection = select_template(
                    candidates,
                    facts,
                    default_template_id=settings.default_template_id if settings else None,
                    language=params.language,
                )
                version_id = selection.candidate.version_id if selection else None
            version = await db.get(BulletinTemplateVersion, version_id) if version_id else None
            if version is None:
                raise NodeError("no_template")
            try:
                bulletin, generated = await create_draft(
                    db,
                    ctx.agents.run_task,
                    DraftInput(
                        workspace_id=ctx.workspace_id,
                        version=version,
                        vulnerability_ids=[vulnerability_id],
                        extra_instructions=params.extra_instructions,
                    ),
                    str(ctx.node_run_id or ctx.run.id),
                    ctx.now,
                )
            except GenerationError as exc:
                ctx.log("draft_failed", error=str(exc))
                out.append({"json": {**data, "bulletin": {"status": "failed", "error": str(exc)}},
                            "meta": entry.get("meta", {})})  # fmt: skip
                continue
            ctx.log("draft_created", ref=bulletin.ref, run_id=str(generated.agent_run_id or ""))
            out.append(
                {
                    "json": {
                        **data,
                        "bulletin": {
                            "status": "draft",
                            "id": str(bulletin.id),
                            "ref": bulletin.ref,
                            "title": bulletin.title,
                        },
                    },
                    "meta": entry.get("meta", {}),
                }
            )
        return {"out": out}
