"""Workflows delivered in every workspace, disabled by default (spec 02 §8, plans 3.11
and 4.14), with the preset agents they use (``app.ai.agents.presets``).

Seeds are created once per workspace (``seed_key``); an analyst activates them. They
are never overwritten afterwards: a later delivery of a seed adds a new version, not
activated, only if the analysts have not modified the workflow.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.presets import seed_agents
from app.bulletins.seeds import seed_templates
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.ids import uuid7
from app.core.rls import init_context, set_context
from app.iam.models import Workspace
from app.workflows.graph import compile_graph, graph_hash
from app.workflows.models import Workflow, WorkflowVersion


def _node(
    node_id: str,
    type_: str,
    name: str,
    x: int,
    y: int,
    settings: dict[str, Any] | None = None,
    **params: Any,
) -> dict[str, Any]:
    node = {
        "id": node_id,
        "type": type_,
        "type_version": 1,
        "name": name,
        "params": params,
        "position": {"x": x, "y": y},
    }
    if settings:
        node["settings"] = settings
    return node


def _edge(
    index: int, source: str, target: str, port: str = "out", to: str = "in"
) -> dict[str, Any]:
    return {
        "id": f"e{index}",
        "from": {"node": source, "port": port},
        "to": {"node": target, "port": to},
    }


# Agents take time (tool loops); a failing agent is reported in its item, not raised.
AGENT_SETTINGS = {"timeout_seconds": 3600}
BY_VULNERABILITY = {"$expr": "json.vulnerability_id"}


def _agent(node_id: str, name: str, preset: str, x: int, y: int, **params: Any) -> dict[str, Any]:
    return _node(
        node_id, "ai.agent", name, x, y, AGENT_SETTINGS, preset=preset, output_key=node_id, **params
    )


def _join(node_id: str, name: str, x: int, y: int) -> dict[str, Any]:
    return _node(node_id, "transform.merge", name, x, y, mode="join", key=BY_VULNERABILITY)


URGENT = {
    "$expr": "json.kev || json.synthesis.output.exploitation_status == 'exploited_itw' "
    "|| json.synthesis.output.suggested_priority == 'P1'"
}

# Spec 07 §5: the main flow, with the watch agents in parallel then the synthesis.
NEW_CVE: dict[str, Any] = {
    "schema_version": 1,
    "nodes": [
        _node("new_cve", "trigger.cve_published", "Nouvelle CVE NVD", 0, 0),
        _node(
            "cve_changed",
            "trigger.cve_updated",
            "CPE ou CVSS ajouté",
            0,
            160,
            change_types=["cpe_added", "cvss_added"],
        ),
        _node("scope", "vuln.scope_match", "Périmètre de veille", 260, 80),
        _node("upsert", "vuln.upsert", "Fiche vulnérabilité", 520, 80),
        _node("enrich", "vuln.enrich", "CVSS, EPSS, KEV", 780, 80),
        _node("technologies", "vuln.match_technologies", "Technologies", 1040, 80),
        _agent("triage", "Triage", "triage", 1300, 80),
        _node(
            "relevant",
            "control.if",
            "Pertinente ?",
            1560,
            80,
            condition={"$expr": "json.triage.output.relevant != `false`"},
        ),
        _agent("poc", "PoC GitHub", "poc_hunter", 1820, -160),
        _agent("social", "Réseaux sociaux", "social", 1820, 0),
        _agent("forums", "Forums techniques", "forums", 1820, 160),
        _agent("vendor", "Avis éditeurs", "vendor", 1820, 320),
        _join("merge_watch", "PoC et réseaux", 2080, -80),
        _join("merge_advice", "Forums et éditeurs", 2080, 240),
        _join("merge_all", "Résultats de veille", 2340, 80),
        _agent("synthesis", "Synthèse", "synthesis", 2600, 80),
        _node("attach", "vuln.attach_analysis", "Enregistrer la synthèse", 2860, 80),
        _node("urgent", "control.if", "KEV, exploitée ou P1", 3120, 80, condition=URGENT),
        _node("notify", "notify.email", "Alerte aux analystes", 3380, 40),
    ],
    "edges": [
        _edge(1, "new_cve", "scope"),
        _edge(2, "cve_changed", "scope"),
        _edge(3, "scope", "upsert", port="in_scope"),
        _edge(4, "upsert", "enrich"),
        _edge(5, "enrich", "technologies"),
        _edge(6, "technologies", "triage"),
        _edge(7, "triage", "relevant"),
        _edge(8, "relevant", "poc", port="true"),
        _edge(9, "relevant", "social", port="true"),
        _edge(10, "relevant", "forums", port="true"),
        _edge(11, "relevant", "vendor", port="true"),
        _edge(12, "poc", "merge_watch"),
        _edge(13, "social", "merge_watch", to="in2"),
        _edge(14, "forums", "merge_advice"),
        _edge(15, "vendor", "merge_advice", to="in2"),
        _edge(16, "merge_watch", "merge_all"),
        _edge(17, "merge_advice", "merge_all", to="in2"),
        _edge(18, "merge_all", "synthesis"),
        _edge(19, "synthesis", "attach"),
        _edge(20, "attach", "urgent"),
        _edge(21, "urgent", "notify", port="true"),
    ],
}

# Spec 07 §5: open vulnerabilities searched again every 6 hours, and at once when a CVE
# enters the KEV catalogue or gets an exploit reference.
REWATCH: dict[str, Any] = {
    "schema_version": 1,
    "nodes": [
        _node(
            "every_6h",
            "trigger.schedule",
            "Toutes les 6 heures",
            0,
            0,
            cron="0 */6 * * *",
            timezone="Europe/Paris",
        ),
        _node(
            "exploited",
            "trigger.cve_updated",
            "Ajout KEV ou exploit",
            0,
            200,
            change_types=["kev_added", "exploit_reference_added"],
        ),
        _node("open", "vuln.list", "Vulnérabilités ouvertes", 260, 0, max_age_days=14, limit=20),
        _node("scope", "vuln.scope_match", "Périmètre de veille", 260, 200),
        _node("upsert", "vuln.upsert", "Fiche vulnérabilité", 520, 200),
        _node("enrich", "vuln.enrich", "CVSS, EPSS, KEV", 780, 200),
        _agent("poc", "PoC GitHub", "poc_hunter", 1040, 0, max_items=20),
        # X searches are rerun for the priority vulnerabilities only (spec 07 §2.1).
        _agent(
            "social",
            "Réseaux sociaux (KEV, P1, P2)",
            "social",
            1040,
            200,
            max_items=20,
            run_if={"$expr": "json.kev || json.priority == 'P1' || json.priority == 'P2'"},
        ),
        _join("merge_watch", "Nouveaux résultats", 1300, 100),
        _agent("synthesis", "Synthèse", "synthesis", 1560, 100, max_items=20),
        _node("attach", "vuln.attach_analysis", "Enregistrer la synthèse", 1820, 100),
        _node("urgent", "control.if", "KEV, exploitée ou P1", 2080, 100, condition=URGENT),
        _node(
            "once",
            "transform.dedupe",
            "Une alerte par vulnérabilité",
            2340,
            60,
            key=BY_VULNERABILITY,
            remember_days=30,
        ),
        _node("notify", "notify.email", "Alerte aux analystes", 2600, 60),
    ],
    "edges": [
        _edge(1, "every_6h", "open"),
        _edge(2, "exploited", "scope"),
        _edge(3, "scope", "upsert", port="in_scope"),
        _edge(4, "upsert", "enrich"),
        _edge(5, "open", "poc"),
        _edge(6, "open", "social"),
        _edge(7, "enrich", "poc"),
        _edge(8, "enrich", "social"),
        _edge(9, "poc", "merge_watch"),
        _edge(10, "social", "merge_watch", to="in2"),
        _edge(11, "merge_watch", "synthesis"),
        _edge(12, "synthesis", "attach"),
        _edge(13, "attach", "urgent"),
        _edge(14, "urgent", "once", port="true"),
        _edge(15, "once", "notify"),
    ],
}

DAILY_WATCH: dict[str, Any] = {
    "schema_version": 1,
    "nodes": [
        _node(
            "daily",
            "trigger.schedule",
            "Chaque matin",
            0,
            0,
            cron="0 7 * * *",
            timezone="Europe/Paris",
        ),
        _node("kev", "source.cisa_kev", "Ajouts KEV du jour", 260, 0, added_within_days=1),
        _node("scope", "vuln.scope_match", "Périmètre de veille", 520, 0),
        _node("upsert", "vuln.upsert", "Fiche vulnérabilité", 780, 0),
        _node("enrich", "vuln.enrich", "CVSS, EPSS, KEV", 1040, 0),
        _node("notify", "notify.email", "Synthèse aux analystes", 1300, 0),
    ],
    "edges": [
        _edge(1, "daily", "kev"),
        _edge(2, "kev", "scope"),
        _edge(3, "scope", "upsert", port="in_scope"),
        _edge(4, "upsert", "enrich"),
        _edge(5, "enrich", "notify"),
    ],
}

SEEDS: dict[str, tuple[str, str, dict[str, Any]]] = {
    "new_cve": (
        "Nouvelle CVE NVD → investigation",
        "Vecteur d'entrée n°1 : chaque CVE publiée (ou qui reçoit des CPE ou un CVSS) est "
        "confrontée au périmètre de veille ; si elle y entre, la fiche est créée, enrichie et "
        "rattachée aux technologies, l'agent de triage juge sa pertinence, les agents de veille "
        "(PoC GitHub, réseaux sociaux, forums, avis éditeurs) cherchent en parallèle, la "
        "synthèse est enregistrée, et les analystes sont alertés si elle est KEV, exploitée ou "
        "P1. Activez d'abord les agents et leurs connecteurs.",
        NEW_CVE,
    ),
    "rewatch": (
        "Re-veille des vulnérabilités ouvertes",
        "Toutes les 6 heures, et dès qu'une CVE entre au catalogue KEV ou reçoit une "
        "référence d'exploit : nouveaux PoC et signalements d'exploitation pour les "
        "vulnérabilités ouvertes depuis moins de 14 jours, synthèse mise à jour, alerte une "
        "seule fois par vulnérabilité.",
        REWATCH,
    ),
    "daily_watch": (
        "Veille quotidienne",
        "Chaque matin, les ajouts au catalogue KEV entrent dans la veille de l'espace. Ajoutez "
        "vos flux RSS (CERT-FR, éditeurs) avec un connecteur RSS.",
        DAILY_WATCH,
    ),
}


async def _refresh(
    db: AsyncSession, workflow: Workflow, graph: dict[str, Any], now: datetime
) -> bool:
    """A newer delivery of a seed: added as a version (not activated) only if every
    version so far was delivered, i.e. the analysts have not edited the workflow."""
    versions = list(
        (
            await db.execute(
                select(WorkflowVersion)
                .where(WorkflowVersion.workflow_id == workflow.id)
                .order_by(WorkflowVersion.version_no)
            )
        ).scalars()
    )
    if not versions or any(v.created_by is not None for v in versions):
        return False
    if versions[-1].graph_hash == graph_hash(graph):
        return False
    db.add(
        WorkflowVersion(
            id=uuid7(),
            workspace_id=workflow.workspace_id,
            workflow_id=workflow.id,
            version_no=versions[-1].version_no + 1,
            graph=graph,
            graph_hash=graph_hash(graph),
            comment="Version livrée (mise à jour)",
            created_at=now,
        )
    )
    return True


async def seed_workspace(db: AsyncSession, workspace_id: uuid.UUID, now: datetime) -> list[str]:
    """Creates the missing seeds of one workspace, and delivers updated ones that were
    not edited (app role, workspace context). Returns the keys created or updated."""
    existing = {
        w.seed_key: w
        for w in (
            await db.execute(
                select(Workflow).where(
                    Workflow.workspace_id == workspace_id, Workflow.seed_key.is_not(None)
                )
            )
        ).scalars()
    }
    created = []
    for key, (name, description, graph) in SEEDS.items():
        compile_graph(graph)  # a broken seed must fail loudly
        if key in existing:
            if await _refresh(db, existing[key], graph, now):
                existing[key].name, existing[key].description = name, description
                existing[key].version += 1
                created.append(key)
            continue
        workflow = Workflow(
            id=uuid7(),
            workspace_id=workspace_id,
            name=name,
            description=description,
            status="draft",
            tags=["seed"],
            seed_key=key,
            version=1,
        )
        db.add(workflow)
        await db.flush()
        db.add(
            WorkflowVersion(
                id=uuid7(),
                workspace_id=workspace_id,
                workflow_id=workflow.id,
                version_no=1,
                graph=graph,
                graph_hash=graph_hash(graph),
                comment="Version livrée",
                created_at=now,
            )
        )
        created.append(key)
    return created


async def seed_all(settings: Settings, now: datetime) -> dict[str, list[str]]:
    """``python -m app.cli seed-workflows`` (after migrations): app role, one workspace
    context at a time. Preset agents first (spec 07 §5), then workflows, then the
    delivered bulletin templates and settings (spec 04)."""
    engine = create_engine(settings.database_url_app.get_secret_value())
    created: dict[str, list[str]] = {}
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            workspaces = (await db.execute(select(Workspace.id, Workspace.slug))).all()
            for workspace_id, slug in workspaces:
                await set_context(db, workspace_ids=(workspace_id,))
                agents = await seed_agents(db, workspace_id, now)
                workflows = await seed_workspace(db, workspace_id, now)
                templates = await seed_templates(db, workspace_id, slug, now)
                created[slug] = [*(f"agent:{a}" for a in agents), *workflows, *templates]
                await db.commit()
    finally:
        await engine.dispose()
    return created
