"""Transformation nodes (spec 02 §7, queue ``default``): pure functions of their inputs,
except ``transform.dedupe`` which remembers keys between runs."""

import hashlib
import json
import re
from typing import ClassVar, Literal

from pydantic import Field

from app.workflows.base import (
    Item,
    NodeCategory,
    NodeContext,
    NodeParams,
    NodeType,
    Outputs,
    expect,
    register_node,
)
from app.workflows.expressions import Expr, Tpl

CVE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.IGNORECASE)
GHSA = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)
MAX_IDS = 100


class TransformNode(NodeType):
    category = NodeCategory.TRANSFORM


class FilterParams(NodeParams):
    condition: Expr


@register_node
class Filter(TransformNode):
    type = "transform.filter"
    label = "Filtrer"
    Params = FilterParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, FilterParams)
        kept = [
            i for i in inputs.get("in", []) if params.condition.truthy(ctx.expression_context(i))
        ]
        return {"out": kept}


FieldValue = Expr | Tpl | str | int | float | bool | None


class MapParams(NodeParams):
    fields: dict[str, FieldValue] = Field(min_length=1, max_length=50)
    keep_existing: bool = True


@register_node
class Map(TransformNode):
    type = "transform.map"
    label = "Définir des champs"
    Params = MapParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, MapParams)
        out = []
        for entry in inputs.get("in", []):
            context = ctx.expression_context(entry)
            data = dict(entry["json"]) if params.keep_existing else {}
            for name, value in params.fields.items():
                if isinstance(value, Expr):
                    data[name] = value.evaluate(context)
                elif isinstance(value, Tpl):
                    data[name] = value.render(context)
                else:
                    data[name] = value
            out.append({"json": data, "meta": entry.get("meta", {})})
        return {"out": out}


class DedupeParams(NodeParams):
    key: Expr = Field(description="Clé de déduplication, par exemple json.url")
    remember_days: int = Field(default=30, ge=0, le=365, description="0 : dans l'exécution seule")


@register_node
class Dedupe(TransformNode):
    type = "transform.dedupe"
    label = "Dédupliquer"
    Params = DedupeParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, DedupeParams)
        seen: set[str] = set()
        out = []
        for entry in inputs.get("in", []):
            value = params.key.evaluate(ctx.expression_context(entry))
            if value in (None, ""):
                continue
            digest = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode())
            key = digest.hexdigest()
            if key in seen:
                continue
            seen.add(key)
            namespace = f"{ctx.run.workflow_id}:{ctx.node_id}"
            if params.remember_days and not await ctx.repo.remember(
                namespace, key, params.remember_days
            ):
                continue
            out.append(entry)
        return {"out": out}


class ExtractCveParams(NodeParams):
    fields: list[str] = Field(default_factory=lambda: ["title", "content"], min_length=1)
    drop_without_match: bool = True


def find_ids(text: str) -> tuple[list[str], list[str]]:
    cves = sorted({m.upper() for m in CVE.findall(text)})[:MAX_IDS]
    ghsas = sorted({"GHSA" + m[4:].lower() for m in GHSA.findall(text)})[:MAX_IDS]
    return cves, ghsas


@register_node
class ExtractCve(TransformNode):
    type = "transform.extract_cve"
    label = "Extraire les CVE et GHSA"
    Params = ExtractCveParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, ExtractCveParams)
        out = []
        for entry in inputs.get("in", []):
            text = "\n".join(str(entry["json"].get(f) or "") for f in params.fields)
            cves, ghsas = find_ids(text)
            if not cves and not ghsas and params.drop_without_match:
                continue
            out.append({**entry, "json": {**entry["json"], "cve_ids": cves, "ghsa_ids": ghsas}})
        return {"out": out}


class MergeParams(NodeParams):
    mode: Literal["concat", "join"] = "concat"
    key: Expr | None = Field(default=None, description="Clé de jointure (mode join)")


@register_node
class Merge(TransformNode):
    type = "transform.merge"
    label = "Fusionner"
    Params = MergeParams
    inputs: ClassVar[tuple[str, ...]] = ("in", "in2")

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, MergeParams)
        left, right = inputs.get("in", []), inputs.get("in2", [])
        if params.mode == "concat" or params.key is None:
            return {"out": [*left, *right]}
        key = params.key

        def k(entry: Item) -> str:
            return json.dumps(key.evaluate(ctx.expression_context(entry)), default=str)

        index: dict[str, Item] = {}
        for entry in right:
            index.setdefault(k(entry), entry)
        out = []
        for entry in left:
            match = index.get(k(entry))
            if match is not None:
                out.append({**entry, "json": {**match["json"], **entry["json"]}})
        return {"out": out}


class LimitParams(NodeParams):
    count: int = Field(ge=1, le=5000)


@register_node
class Limit(TransformNode):
    type = "transform.limit"
    label = "Limiter"
    Params = LimitParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, LimitParams)
        return {"out": inputs.get("in", [])[: params.count]}
