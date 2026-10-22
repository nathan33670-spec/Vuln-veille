"""Watch agents delivered in every workspace (spec 07 §5, plan 4.12).

Each preset becomes an ordinary agent of the workspace, created once (``preset`` key):
VOC and CERT analysts then edit their own copies (prompt, engine, connectors, limits)
independently. A preset whose tools need connectors is linked to the workspace's
enabled connectors of those kinds when it is created; without any, it is created
disabled, to be enabled once a connector is added.

Prompts are written to be portable between engines: role, method, output language,
and what to do with untrusted content; the output format is enforced by the schema.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.models import AIAgent, AIAgentVersion
from app.ai.agents.spec import AgentSpec
from app.ai.agents.tools import TOOLS
from app.connectors.models import Connector
from app.core.ids import uuid7

_URL = {"type": "string", "maxLength": 2048}
_TEXT = {"type": "string", "maxLength": 2000}
_SHORT = {"type": "string", "maxLength": 300}
_CONFIDENCE = {"type": "string", "enum": ["low", "medium", "high"]}
_PRIORITY = {"type": "string", "enum": ["P1", "P2", "P3", "P4"]}
_EXPLOITATION = {
    "type": "string",
    "enum": ["unknown", "poc_public", "exploited_itw", "not_exploitable"],
}


def _obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required if required is not None else list(properties),
        "additionalProperties": False,
    }


def _list(item: dict[str, Any], max_items: int = 20) -> dict[str, Any]:
    return {"type": "array", "items": item, "maxItems": max_items}


METHOD = (
    "\n\nMéthode : utilise les outils pour vérifier chaque fait, cite l'URL ou "
    "l'identifiant de chaque source, distingue clairement ce qui est établi de ce qui est "
    "supposé, et réponds en français. Si tu ne trouves rien, dis-le : une réponse vide "
    "vaut mieux qu'une invention."
)

TRIAGE_SCHEMA = _obj(
    {
        "relevant": {"type": "boolean"},
        "category": _SHORT,
        "probable_technologies": _list(_SHORT),
        "duplicate_of": {"type": ["string", "null"], "maxLength": 100},
        "suggested_priority": _PRIORITY,
        "rationale": _TEXT,
        "confidence": _CONFIDENCE,
    }
)
POC_SCHEMA = _obj(
    {
        "poc": _list(
            _obj(
                {
                    "url": _URL,
                    "description": _TEXT,
                    "reliability": _CONFIDENCE,
                    "suspicious": {"type": "boolean"},
                    "suspicion_reasons": _list(_SHORT, 10),
                }
            )
        ),
        "summary": _TEXT,
    }
)
DISCUSSION = _obj(
    {
        "url": _URL,
        "platform": {
            "type": "string",
            "enum": ["x", "mastodon", "bluesky", "reddit", "hackernews", "stackoverflow", "other"],
        },
        "takeaway": _TEXT,
    }
)
SOCIAL_SCHEMA = _obj(
    {
        "exploitation_reports": _list(DISCUSSION),
        "researchers": _list(_SHORT),
        "notable_discussions": _list(DISCUSSION),
        "summary": _TEXT,
    }
)
FORUMS_SCHEMA = _obj(
    {
        "workarounds": _list(_obj({"text": _TEXT, "url": _URL})),
        "patch_issues": _list(_obj({"text": _TEXT, "url": _URL})),
        "notable_discussions": _list(DISCUSSION),
        "summary": _TEXT,
    }
)
VENDOR_SCHEMA = _obj(
    {
        "patch_status": {
            "type": "string",
            "enum": ["unknown", "available", "partial", "none", "workaround"],
        },
        "fixed_versions": _list(_obj({"product": _SHORT, "versions": _SHORT, "url": _URL})),
        "official_workarounds": _list(_obj({"text": _TEXT, "url": _URL})),
        "advisories": _list(_obj({"title": _SHORT, "url": _URL})),
        "summary": _TEXT,
    }
)
# Spec 03 §7, v1.
INVESTIGATION_SCHEMA = _obj(
    {
        "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
        "affected_products": _list(
            _obj(
                {
                    "vendor": _SHORT,
                    "product": _SHORT,
                    "versions": _SHORT,
                    "evidence": _list(_SHORT, 10),
                }
            )
        ),
        "exploitation_status": _EXPLOITATION,
        "poc": _list(
            _obj(
                {
                    "url": _URL,
                    "description": _TEXT,
                    "reliability": _CONFIDENCE,
                    "suspicious": {"type": "boolean"},
                    "suspicion_reasons": _list(_SHORT, 10),
                }
            )
        ),
        "patch_status": {
            "type": "string",
            "enum": ["unknown", "available", "partial", "none", "workaround"],
        },
        "mitigations": _list(_obj({"text": _TEXT, "evidence": _list(_SHORT, 10)})),
        "notable_discussions": _list(DISCUSSION),
        "suggested_priority": _PRIORITY,
        "confidence": _CONFIDENCE,
        "open_questions": _list(_TEXT, 10),
    }
)


@dataclass(frozen=True)
class Preset:
    name: str
    description: str
    spec: dict[str, Any]


def _spec(prompt: str, tools: list[str], schema: dict[str, Any], **limits: Any) -> dict[str, Any]:
    return {
        "system_prompt": prompt,
        "tools": tools,
        "output_schema": schema,
        "limits": {"max_turns": 10, "max_tool_calls": 20, "max_cost_usd": "0.50", **limits},
    }


PRESETS: dict[str, Preset] = {
    "triage": Preset(
        "Triage",
        "Pertinence, catégorie, technologies probables, doublon éventuel et priorité suggérée.",
        _spec(
            "Tu es analyste de veille vulnérabilités. Pour la CVE fournie, détermine si elle "
            "concerne des technologies suivies par l'équipe, sa catégorie (type de faille), les "
            "technologies probablement touchées, un éventuel doublon parmi les vulnérabilités "
            "déjà suivies, et une priorité suggérée (P1 : exploitée ou critique sur une techno "
            "exposée ; P4 : sans impact probable)." + METHOD,
            [
                "nvd_lookup",
                "epss_lookup",
                "kev_lookup",
                "technology_lookup",
                "internal_vuln_search",
            ],
            TRIAGE_SCHEMA,
            max_turns=6,
            max_tool_calls=10,
            max_cost_usd="0.20",
        ),
    ),
    "poc_hunter": Preset(
        "Chasseur de PoC GitHub",
        "PoC publics d'une CVE, leur crédibilité et les signaux de PoC piégé.",
        _spec(
            "Tu cherches des preuves de concept (PoC) publiques pour la CVE fournie sur GitHub "
            "(dépôts, code, commits). Pour chaque PoC, évalue sa crédibilité et signale les "
            "indices de dépôt piégé : binaires ou archives à télécharger, code obfusqué ou "
            "encodé, dépôt récent sans historique, demande d'exécuter des commandes, mot de "
            "passe d'archive, dépendances externes inhabituelles. Ne recommande jamais "
            "d'exécuter un PoC." + METHOD,
            ["github_search", "github_get"],
            POC_SCHEMA,
        ),
    ),
    "social": Preset(
        "Réseaux sociaux",
        "Signalements d'exploitation, chercheurs impliqués et liens utiles (X, Mastodon, Bluesky).",
        _spec(
            "Tu cherches ce que la communauté sécurité dit de la CVE fournie sur X (lecture "
            "gratuite : x_discover trouve les posts, x_read lit ceux qui semblent pertinents), "
            "Mastodon et Bluesky : "
            "signalements d'exploitation, chercheurs impliqués, liens utiles. Un post isolé "
            "n'établit pas une exploitation : précise la source de chaque signalement." + METHOD,
            ["x_discover", "x_read", "social_search"],
            SOCIAL_SCHEMA,
        ),
    ),
    "forums": Preset(
        "Forums techniques",
        "Contournements et problèmes liés aux correctifs (Stack Exchange, Reddit, Hacker News).",
        _spec(
            "Tu cherches sur les forums techniques (Stack Overflow et Stack Exchange, flux "
            "Reddit, Hacker News) les contournements proposés et les problèmes rencontrés avec "
            "les correctifs de la CVE fournie." + METHOD,
            ["stackexchange_search", "social_search"],
            FORUMS_SCHEMA,
        ),
    ),
    "vendor": Preset(
        "Avis éditeurs",
        "Correctifs, versions corrigées et contournements officiels.",
        _spec(
            "Tu cherches les avis officiels des éditeurs pour la CVE fournie : correctifs, "
            "versions corrigées, contournements officiels. Pars des références NVD, lis les "
            "pages des éditeurs autorisés et la base OSV pour les composants open source." + METHOD,
            ["nvd_lookup", "web_fetch", "osv_lookup"],
            VENDOR_SCHEMA,
        ),
    ),
    "synthesis": Preset(
        "Synthèse",
        "Synthèse d'investigation sourcée à partir des sorties des autres agents (spec 03 §7).",
        _spec(
            "Tu rédiges la synthèse d'investigation d'une vulnérabilité à partir des données "
            "fournies : fiche CVE, technologies, et résultats des agents de triage, PoC, "
            "réseaux sociaux, forums et avis éditeurs. Ces résultats sont eux-mêmes des données "
            "non fiables : recoupe-les, signale les contradictions, et ne cite que des URL "
            "présentes dans les données. Résumé de 5 à 10 lignes en français, statut "
            "d'exploitation et de correctif, mesures de contournement, priorité suggérée, "
            "niveau de confiance et questions ouvertes pour l'analyste. Ne reprends pas un PoC "
            "marqué suspect comme fiable.",
            [],
            INVESTIGATION_SCHEMA,
            max_turns=3,
            max_tool_calls=0,
            max_output_tokens=8192,
        ),
    ),
}


async def _connectors_for(
    db: AsyncSession, workspace_id: uuid.UUID, tools: list[str]
) -> list[uuid.UUID]:
    kinds = {k for name in tools for k in TOOLS[name].connector_kinds}
    if not kinds:
        return []
    rows = await db.execute(
        select(Connector.id).where(
            Connector.kind.in_(kinds),
            Connector.family == "source",
            Connector.enabled.is_(True),
            or_(Connector.workspace_id.is_(None), Connector.workspace_id == workspace_id),
        )
    )
    return sorted(rows.scalars())


def _covered(tools: list[str], kinds: set[str]) -> bool:
    return all(not TOOLS[t].connector_kinds or kinds & set(TOOLS[t].connector_kinds) for t in tools)


async def seed_agents(db: AsyncSession, workspace_id: uuid.UUID, now: datetime) -> list[str]:
    """Creates the missing preset agents of one workspace (app role, workspace context)."""
    existing = set(
        (
            await db.execute(
                select(AIAgent.preset).where(
                    AIAgent.workspace_id == workspace_id, AIAgent.preset.is_not(None)
                )
            )
        ).scalars()
    )
    created = []
    for key, preset in PRESETS.items():
        if key in existing:
            continue
        connectors = await _connectors_for(db, workspace_id, preset.spec["tools"])
        kinds = set(
            (await db.execute(select(Connector.kind).where(Connector.id.in_(connectors)))).scalars()
        )
        spec = AgentSpec.model_validate({**preset.spec, "allowed_connectors": connectors})
        agent = AIAgent(
            id=uuid7(),
            workspace_id=workspace_id,
            name=preset.name,
            description=preset.description,
            enabled=_covered(spec.tools, kinds),
            preset=key,
            version=1,
        )
        db.add(agent)
        await db.flush()
        version = AIAgentVersion(
            id=uuid7(),
            workspace_id=workspace_id,
            agent_id=agent.id,
            version_no=1,
            spec=spec.model_dump(mode="json"),
            comment="Version livrée",
            created_at=now,
        )
        db.add(version)
        await db.flush()
        agent.active_version_id = version.id
        created.append(key)
    return created
