"""Workflows delivered in every workspace, disabled by default (spec 02 §8, plan 3.11).

Seeds are created once per workspace (``seed_key``); an analyst activates them. They
are never overwritten afterwards: a later delivery of a seed adds a new version only
if the analyst has not modified the workflow.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.ids import uuid7
from app.core.rls import init_context, set_context
from app.iam.models import Workspace
from app.workflows.graph import compile_graph, graph_hash
from app.workflows.models import Workflow, WorkflowVersion


def _node(node_id: str, type_: str, name: str, x: int, y: int, **params: Any) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": type_,
        "type_version": 1,
        "name": name,
        "params": params,
        "position": {"x": x, "y": y},
    }


def _edge(
    index: int, source: str, target: str, port: str = "out", to: str = "in"
) -> dict[str, Any]:
    return {
        "id": f"e{index}",
        "from": {"node": source, "port": port},
        "to": {"node": target, "port": to},
    }


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
        _node("upsert", "vuln.upsert", "Fiche vulnérabilité", 520, 40),
        _node("enrich", "vuln.enrich", "CVSS, EPSS, KEV", 780, 40),
        _node("technologies", "vuln.match_technologies", "Technologies", 1040, 40),
        _node(
            "urgent",
            "control.if",
            "KEV ou critique",
            1300,
            40,
            condition={"$expr": "json.kev || json.severity == 'CRITICAL'"},
        ),
        _node("notify", "notify.email", "Alerte aux analystes", 1560, 0),
    ],
    "edges": [
        _edge(1, "new_cve", "scope"),
        _edge(2, "cve_changed", "scope"),
        _edge(3, "scope", "upsert", port="in_scope"),
        _edge(4, "upsert", "enrich"),
        _edge(5, "enrich", "technologies"),
        _edge(6, "technologies", "urgent"),
        _edge(7, "urgent", "notify", port="true"),
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
        "Nouvelle CVE NVD",
        "Vecteur d'entrée n°1 : chaque CVE publiée (ou qui reçoit des CPE ou un CVSS) est "
        "confrontée au périmètre de veille ; si elle y entre, la fiche est créée, enrichie et "
        "rattachée aux technologies, et les analystes sont alertés si elle est KEV ou critique.",
        NEW_CVE,
    ),
    "daily_watch": (
        "Veille quotidienne",
        "Chaque matin, les ajouts au catalogue KEV entrent dans la veille de l'espace. Ajoutez "
        "vos flux RSS (CERT-FR, éditeurs) avec un connecteur RSS.",
        DAILY_WATCH,
    ),
}


async def seed_workspace(db: AsyncSession, workspace_id: uuid.UUID, now: datetime) -> list[str]:
    """Creates the missing seeds of one workspace (app role, workspace context)."""
    existing = set(
        (
            await db.execute(
                select(Workflow.seed_key).where(
                    Workflow.workspace_id == workspace_id, Workflow.seed_key.is_not(None)
                )
            )
        ).scalars()
    )
    created = []
    for key, (name, description, graph) in SEEDS.items():
        if key in existing:
            continue
        compile_graph(graph)  # a broken seed must fail loudly
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
    context at a time."""
    engine = create_engine(settings.database_url_app.get_secret_value())
    created: dict[str, list[str]] = {}
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            workspaces = (await db.execute(select(Workspace.id, Workspace.slug))).all()
            for workspace_id, slug in workspaces:
                await set_context(db, workspace_ids=(workspace_id,))
                created[slug] = await seed_workspace(db, workspace_id, now)
                await db.commit()
    finally:
        await engine.dispose()
    return created
