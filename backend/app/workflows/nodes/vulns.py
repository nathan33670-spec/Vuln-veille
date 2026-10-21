"""Vulnerability nodes (spec 02 §7, queue ``default``). Items carry ``json.cve_id``;
``vuln.upsert`` also accepts ``json.cve_ids`` (from ``transform.extract_cve``).

Records are shared between teams and the assessment is per team (ADR-024): upserting
opens this workspace's assessment as ``new`` (unqualified) on the shared record.
"""

import re
import uuid
from typing import ClassVar, Literal

from pydantic import Field

from app.watch.scope import match
from app.workflows.base import (
    Item,
    NodeCategory,
    NodeContext,
    NodeError,
    NodeParams,
    NodeType,
    Outputs,
    expect,
    item,
    register_node,
)
from app.workflows.repo import cve_summary

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}$")
MAX_CVES_PER_ITEM = 20


def _cve_id(entry: Item) -> str | None:
    value = entry.get("json", {}).get("cve_id")
    return value.upper() if isinstance(value, str) and CVE_ID.fullmatch(value.upper()) else None


def _with(entry: Item, **fields: object) -> Item:
    return {"json": {**entry["json"], **fields}, "meta": entry.get("meta", {})}


class VulnNode(NodeType):
    category = NodeCategory.VULN


class ScopeMatchParams(NodeParams):
    pending_as: Literal["out_of_scope", "in_scope"] = Field(
        default="out_of_scope",
        description="Sortie des CVE en attente de score (réévaluées quand NVD ajoute le CVSS)",
    )


@register_node
class ScopeMatch(VulnNode):
    type = "vuln.scope_match"
    label = "Périmètre de veille"
    Params = ScopeMatchParams
    outputs: ClassVar[tuple[str, ...]] = ("in_scope", "out_of_scope")

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, ScopeMatchParams)
        scope, technologies = await ctx.repo.scope()
        result: Outputs = {"in_scope": [], "out_of_scope": []}
        for entry in inputs.get("in", []):
            cve_id = _cve_id(entry)
            cve = await ctx.repo.cve(cve_id) if cve_id else None
            if cve is None:
                result["out_of_scope"].append(_with(entry, scope={"decision": "unknown_cve"}))
                continue
            decision = match(scope, cve, technologies)
            port = decision.decision if decision.decision != "pending" else params.pending_as
            verdict = {"decision": decision.decision, "reasons": decision.reasons}
            result[port].append(_with(entry, cve_id=cve_id, scope=verdict))
        ctx.log("scope", in_scope=len(result["in_scope"]), out=len(result["out_of_scope"]))
        return result


class UpsertParams(NodeParams):
    attach_evidence: bool = Field(
        default=True, description="Rattacher l'élément collecté comme preuve"
    )
    evidence_kind: Literal[
        "advisory", "poc", "exploit", "patch", "discussion", "mention", "news"
    ] = "mention"


@register_node
class Upsert(VulnNode):
    type = "vuln.upsert"
    label = "Créer ou mettre à jour la vulnérabilité"
    Params = UpsertParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, UpsertParams)
        out = []
        for entry in inputs.get("in", []):
            first = _cve_id(entry)
            ids = [first] if first else []
            ids += [
                c.upper()
                for c in entry["json"].get("cve_ids") or []
                if isinstance(c, str) and CVE_ID.fullmatch(c.upper())
            ]
            collected = entry["json"].get("collected_item_id")
            for cve_id in list(dict.fromkeys(ids))[:MAX_CVES_PER_ITEM]:
                vulnerability, created = await ctx.repo.upsert_vulnerability(cve_id)
                attached = False
                if params.attach_evidence and isinstance(collected, str):
                    attached = await ctx.repo.attach_evidence(
                        vulnerability, uuid.UUID(collected), params.evidence_kind
                    )
                out.append(
                    _with(
                        entry,
                        cve_id=cve_id,
                        vulnerability_id=str(vulnerability.id),
                        ref=vulnerability.ref,
                        created=created,
                        evidence_attached=attached,
                    )
                )
        ctx.log("upserted", count=len(out), created=sum(1 for i in out if i["json"]["created"]))
        return {"out": out}


async def _vulnerability(ctx: NodeContext, entry: Item):  # type: ignore[no-untyped-def]
    raw = entry["json"].get("vulnerability_id")
    try:
        vulnerability_id = uuid.UUID(str(raw))
    except ValueError:
        raise NodeError("vulnerability_id_missing") from None
    vulnerability = await ctx.repo.vulnerability(vulnerability_id)
    if vulnerability is None:
        raise NodeError("vulnerability_not_found")
    return vulnerability


class EnrichParams(NodeParams):
    mark_kev_exploited: bool = Field(
        default=True, description="Marquer « exploitée » une CVE du catalogue KEV"
    )


@register_node
class Enrich(VulnNode):
    type = "vuln.enrich"
    label = "Enrichir (CVSS, EPSS, KEV)"
    Params = EnrichParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, EnrichParams)
        out = []
        for entry in inputs.get("in", []):
            vulnerability = await _vulnerability(ctx, entry)
            cve = await ctx.repo.cve(vulnerability.cve_id) if vulnerability.cve_id else None
            summary = cve_summary(cve) if cve else {}
            if cve is not None and cve.kev is not None and params.mark_kev_exploited:
                await ctx.repo.mark_exploited(vulnerability, "kev")
            out.append(
                _with(
                    entry,
                    cve=summary,
                    kev=bool(summary.get("kev")),
                    severity=summary.get("severity"),
                    base_score=summary.get("base_score"),
                    epss_score=summary.get("epss_score"),
                    exploitation_status=vulnerability.exploitation_status,
                )
            )
        return {"out": out}


@register_node
class MatchTechnologies(VulnNode):
    type = "vuln.match_technologies"
    label = "Rattacher les technologies (CPE)"

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        out = []
        for entry in inputs.get("in", []):
            vulnerability = await _vulnerability(ctx, entry)
            cve = await ctx.repo.cve(vulnerability.cve_id) if vulnerability.cve_id else None
            linked = await ctx.repo.link_technologies(vulnerability, cve)
            technologies = [
                {"id": str(t.id), "vendor": t.vendor, "product": t.product, "name": t.display_name}
                for t in linked
            ]
            out.append(_with(entry, technologies=technologies))
        return {"out": out}


class ListParams(NodeParams):
    state: Literal["unqualified", "open", "all"] = "open"
    max_age_days: int | None = Field(default=14, ge=1, le=3650)
    limit: int = Field(default=100, ge=1, le=1000)


@register_node
class ListVulnerabilities(VulnNode):
    type = "vuln.list"
    label = "Lister les vulnérabilités de l'espace"
    Params = ListParams
    runs_without_items = True

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, ListParams)
        rows = await ctx.repo.list_vulnerabilities(
            state=params.state, max_age_days=params.max_age_days, limit=params.limit
        )
        return {
            "out": [
                item(
                    {
                        "vulnerability_id": str(v.id),
                        "ref": v.ref,
                        "cve_id": v.cve_id,
                        "title": v.title,
                        "status": a.status if a else None,
                        "priority": a.priority if a else None,
                        "exploitation_status": v.exploitation_status,
                    },
                    source="vulnerabilities",
                )
                for v, a in rows
            ]
        }


class AttachAnalysisParams(NodeParams):
    field: str = Field(
        default="synthesis",
        pattern=r"^[a-z][a-z0-9_]{0,39}$",
        description="Clé de l'élément qui porte le résultat de l'agent (ai.agent)",
    )


@register_node
class AttachAnalysis(VulnNode):
    """Stores an agent's validated output as the vulnerability's analysis (history kept).
    Only succeeded runs are stored; their injection signals go with them."""

    type = "vuln.attach_analysis"
    label = "Enregistrer la synthèse IA"
    Params = AttachAnalysisParams

    async def execute(self, ctx: NodeContext, params: NodeParams, inputs: Outputs) -> Outputs:
        params = expect(params, AttachAnalysisParams)
        out = []
        for entry in inputs.get("in", []):
            result = entry["json"].get(params.field)
            if not isinstance(result, dict) or result.get("status") != "succeeded":
                out.append(_with(entry, analysis_id=None))
                continue
            output = result.get("output")
            if not isinstance(output, dict):
                raise NodeError("analysis_output_missing")
            vulnerability = await _vulnerability(ctx, entry)
            run_id = result.get("run_id")
            flags = result.get("injection_flags")
            analysis_id = await ctx.repo.attach_analysis(
                vulnerability,
                output,
                uuid.UUID(run_id) if isinstance(run_id, str) else None,
                flags if isinstance(flags, list) else [],
            )
            out.append(_with(entry, analysis_id=str(analysis_id)))
        ctx.log("analyses", stored=sum(1 for i in out if i["json"]["analysis_id"]))
        return {"out": out}
