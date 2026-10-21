"""AI nodes (spec 02 §7, queue ``ai``): agents of the workspace and simple AI tasks.

Every call goes through the agent runtime (budgets, tracing, injection guards). An
item's data reaches the engine only as an untrusted document; the node's own text
(instructions, labels, schema) is operator configuration. What the node passes on
is the validated output under ``output_key``, with the run's status, cost and
injection signals: an agent that fails or is refused does not stop the workflow, the
next nodes see its status. A missing agent, or nodes without agent access, do.
"""

import uuid
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from app.ai.agents.guards import bounded
from app.ai.agents.invoke import AgentNotFoundError
from app.ai.agents.spec import AgentSpec
from app.iam.permissions import Permission
from app.workflows.base import (
    AgentAccess,
    Item,
    NodeCategory,
    NodeContext,
    NodeError,
    NodeParams,
    NodeType,
    Outputs,
    Reference,
    expect,
    register_node,
)
from app.workflows.expressions import Expr

OUTPUT_KEY = r"^[a-z][a-z0-9_]{0,39}$"
MAX_PAYLOAD_CHARS = 60_000
TASK_LIMITS = {"max_turns": 2, "max_tool_calls": 0, "max_cost_usd": "0.10"}
PresetKey = Literal["triage", "poc_hunter", "social", "forums", "vendor", "synthesis"]


class AINode(NodeType):
    category = NodeCategory.AI
    queue = "ai"
    required_permissions: ClassVar[frozenset[Permission]] = frozenset({Permission.AI_AGENT_RUN})


class _Common(NodeParams):
    input: Expr | None = Field(
        default=None, description="Données envoyées au modèle (par défaut : tout l'élément)"
    )
    output_key: str = Field(default="ai", pattern=OUTPUT_KEY)
    max_items: int = Field(default=10, ge=1, le=50, description="Éléments traités au maximum")


def _access(ctx: NodeContext) -> AgentAccess:
    if ctx.agents is None:
        raise NodeError("agents_unavailable")
    return ctx.agents


def _payload(ctx: NodeContext, params: _Common, entry: Item) -> dict[str, Any]:
    value = (
        params.input.evaluate(ctx.expression_context(entry))
        if params.input is not None
        else entry.get("json", {})
    )
    data = value if isinstance(value, dict) else {"value": value}
    return dict(bounded(data, MAX_PAYLOAD_CHARS))


def _context_id(ctx: NodeContext) -> str:
    return str(ctx.node_run_id or ctx.run.id)


async def _each(ctx: NodeContext, params: _Common, inputs: Outputs, call: Any) -> Outputs:
    entries = inputs.get("in", [])
    if len(entries) > params.max_items:
        ctx.log("items_capped", received=len(entries), processed=params.max_items)
    out = []
    for entry in entries[: params.max_items]:
        result = await call(_payload(ctx, params, entry))
        ctx.log("ai_run", status=result.status, run_id=str(result.run_id or ""))
        out.append(
            {
                "json": {**entry.get("json", {}), params.output_key: result.as_dict()},
                "meta": {**entry.get("meta", {}), "ai": params.output_key},
            }
        )
    return {"out": out}


# ai.agent -----------------------------------------------------------------------


class AgentParams(_Common):
    agent_id: uuid.UUID | None = Field(default=None, description="Agent de l'espace")
    preset: PresetKey | None = Field(default=None, description="Ou agent prédéfini de l'espace")
    output_key: str = Field(default="agent", pattern=OUTPUT_KEY)

    @model_validator(mode="after")
    def _one(self) -> "AgentParams":
        if (self.agent_id is None) == (self.preset is None):
            raise ValueError("agent_id or preset, exactly one")
        return self


@register_node
class AgentNode(AINode):
    type = "ai.agent"
    label = "Agent IA de l'espace"
    Params = AgentParams

    def references(self, params: NodeParams) -> list[Reference]:
        agent_id = expect(params, AgentParams).agent_id
        return [Reference("agent", agent_id)] if agent_id else []

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, AgentParams)
        access = _access(ctx)

        async def call(payload: dict[str, Any]) -> Any:
            return await access.run_agent(params.agent_id, params.preset, payload, _context_id(ctx))

        try:
            return await _each(ctx, params, inputs, call)
        except AgentNotFoundError:
            raise NodeError("agent_not_found") from None


# Tasks without an agent ------------------------------------------------------------


def _task_spec(prompt: str, schema: dict[str, Any]) -> AgentSpec:
    return AgentSpec.model_validate(
        {"system_prompt": prompt, "output_schema": schema, "limits": TASK_LIMITS}
    )


async def _task(
    ctx: NodeContext, params: _Common, inputs: Outputs, task: str, spec: AgentSpec
) -> Outputs:
    access = _access(ctx)

    async def call(payload: dict[str, Any]) -> Any:
        return await access.run_task(task, spec, payload, _context_id(ctx))

    return await _each(ctx, params, inputs, call)


class SummarizeParams(_Common):
    instructions: str = Field(
        default="Résume en français, de façon factuelle, en citant les URL utiles.",
        max_length=2000,
    )
    max_words: int = Field(default=150, ge=20, le=1000)
    output_key: str = Field(default="summary", pattern=OUTPUT_KEY)


@register_node
class Summarize(AINode):
    type = "ai.summarize"
    label = "Résumer (IA)"
    Params = SummarizeParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, SummarizeParams)
        schema = {
            "type": "object",
            "properties": {"summary": {"type": "string", "maxLength": params.max_words * 12}},
            "required": ["summary"],
            "additionalProperties": False,
        }
        prompt = f"{params.instructions}\nEn {params.max_words} mots au plus."
        return await _task(ctx, params, inputs, self.type, _task_spec(prompt, schema))


class ClassifyParams(_Common):
    labels: list[str] = Field(min_length=2, max_length=30)
    multiple: bool = Field(default=False, description="Plusieurs étiquettes possibles")
    instructions: str = Field(default="Classe l'élément.", max_length=2000)
    output_key: str = Field(default="classification", pattern=OUTPUT_KEY)

    @field_validator("labels")
    @classmethod
    def _labels(cls, value: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(v.strip() for v in value if v.strip()))
        if len(cleaned) < 2 or any(len(v) > 100 for v in cleaned):  # noqa: PLR2004
            raise ValueError("2 to 30 distinct labels of at most 100 characters")
        return cleaned


@register_node
class Classify(AINode):
    type = "ai.classify"
    label = "Classer (IA)"
    Params = ClassifyParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, ClassifyParams)
        label = {"type": "string", "enum": params.labels}
        chosen = (
            {"labels": {"type": "array", "items": label, "maxItems": len(params.labels)}}
            if params.multiple
            else {"label": label}
        )
        schema = {
            "type": "object",
            "properties": {**chosen, "rationale": {"type": "string", "maxLength": 1000}},
            "required": [*chosen, "rationale"],
            "additionalProperties": False,
        }
        prompt = f"{params.instructions}\nÉtiquettes possibles uniquement celles du schéma."
        return await _task(ctx, params, inputs, self.type, _task_spec(prompt, schema))


class ExtractParams(_Common):
    output_schema: dict[str, Any] = Field(description="JSON Schema de l'objet à extraire")
    instructions: str = Field(
        default="Extrais les informations demandées ; laisse vide ce qui est absent.",
        max_length=2000,
    )
    output_key: str = Field(default="extracted", pattern=OUTPUT_KEY)

    @field_validator("output_schema")
    @classmethod
    def _schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        _task_spec("check", value)  # same rules as an agent's output schema
        return value


@register_node
class Extract(AINode):
    type = "ai.extract"
    label = "Extraire (IA)"
    Params = ExtractParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, ExtractParams)
        spec = _task_spec(params.instructions, params.output_schema)
        return await _task(ctx, params, inputs, self.type, spec)


class RelevanceParams(_Common):
    profile: Literal["technologies", "text"] = Field(
        default="technologies",
        description="Technologies du périmètre de veille, ou profil rédigé",
    )
    profile_text: str = Field(default="", max_length=4000)
    output_key: str = Field(default="relevance", pattern=OUTPUT_KEY)

    @model_validator(mode="after")
    def _text(self) -> "RelevanceParams":
        if self.profile == "text" and not self.profile_text.strip():
            raise ValueError("profile_text is required for a written profile")
        return self


RELEVANCE_SCHEMA = {
    "type": "object",
    "properties": {
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "matched": {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 20},
        "reasons": {"type": "string", "maxLength": 1000},
    },
    "required": ["score", "matched", "reasons"],
    "additionalProperties": False,
}


@register_node
class Relevance(AINode):
    type = "ai.relevance"
    label = "Pertinence (IA)"
    Params = RelevanceParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, RelevanceParams)
        if params.profile == "technologies":
            _, technologies = await ctx.repo.scope()
            names = sorted({t.display_name for t in technologies})[:300]
            profile = "Technologies suivies par l'équipe : " + ", ".join(names or ["(aucune)"])
        else:
            profile = params.profile_text
        prompt = (
            "Évalue de 0 à 100 la pertinence de l'élément pour l'équipe, cite les technologies "
            "ou thèmes du profil qui correspondent et justifie brièvement.\n" + profile
        )
        spec = _task_spec(prompt, RELEVANCE_SCHEMA)
        return await _task(ctx, params, inputs, self.type, spec)
