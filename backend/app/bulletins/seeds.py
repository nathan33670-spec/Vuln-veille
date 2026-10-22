"""Templates delivered with each workspace (Q39), and its bulletin settings.

A generic template per language (the French one is the default template, used when no
rule matches) and a priority template for exploited or critical vulnerabilities. They
are ordinary templates: analysts can change them (new versions) or archive them.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.bulletins.models import BulletinSettings, BulletinTemplate, BulletinTemplateVersion
from app.bulletins.spec import parse_spec
from app.core.ids import uuid7

SOURCES_RULE = {
    "fr": "N'affirme que ce que les sources fournies établissent, et cite-les par leur URL.",
    "en": "Only state what the provided sources establish, and cite them by URL.",
}


def _fields(language: str, *, urgent: bool) -> list[dict[str, Any]]:
    fr = language == "fr"
    rule = SOURCES_RULE[language]

    def ai(text_fr: str, text_en: str) -> dict[str, Any]:
        return {"mode": "ai", "instructions": f"{text_fr if fr else text_en} {rule}"}

    fields: list[dict[str, Any]] = [
        {
            "key": "title",
            "label": "Titre" if fr else "Title",
            "type": "text",
            "required": True,
            "max_length": 160,
            "generation": ai(
                "Titre court : produit, type de vulnérabilité, impact.",
                "Short title: product, vulnerability type, impact.",
            ),
        },
        {
            "key": "severity",
            "label": "Sévérité" if fr else "Severity",
            "type": "enum",
            "options": ["critical", "high", "medium", "low"],
            "generation": {"mode": "computed", "from": "vuln.severity"},
        },
        {
            "key": "cves",
            "label": "CVE",
            "type": "list",
            "generation": {"mode": "computed", "from": "vuln.cve_ids"},
        },
        {
            "key": "cvss",
            "label": "CVSS",
            "type": "cvss",
            "generation": {"mode": "computed", "from": "vuln.cvss"},
        },
        {
            "key": "summary",
            "label": "Résumé" if fr else "Summary",
            "type": "markdown",
            "required": True,
            "max_length": 2000,
            "generation": ai(
                "Résumé en cinq lignes au plus, pour un RSSI.",
                "Summary in five lines at most, for a CISO.",
            ),
        },
        {
            "key": "affected_products",
            "label": "Produits concernés" if fr else "Affected products",
            "type": "products",
            "max_items": 30,
            "generation": ai(
                "Uniquement les produits et versions confirmés par les sources.",
                "Only the products and versions confirmed by the sources.",
            ),
        },
        {
            "key": "exploitation",
            "label": "Exploitation",
            "type": "markdown",
            "max_length": 1500,
            "generation": ai(
                "État de l'exploitation et disponibilité de preuves de concept.",
                "Exploitation status and availability of proofs of concept.",
            ),
        },
        {
            "key": "recommendations",
            "label": "Recommandations" if fr else "Recommendations",
            "type": "markdown",
            "required": True,
            "max_length": 2500,
            "generation": ai(
                "Actions concrètes et urgentes d'abord : correctifs, contournements, détection."
                if urgent
                else "Actions concrètes : correctifs, contournements, détection.",
                "Concrete and urgent actions first: patches, workarounds, detection."
                if urgent
                else "Concrete actions: patches, workarounds, detection.",
            ),
        },
        {
            "key": "references",
            "label": "Références" if fr else "References",
            "type": "references",
            "generation": {"mode": "computed", "from": "evidence.references"},
        },
        {
            "key": "analyst_note",
            "label": "Note de l'analyste" if fr else "Analyst note",
            "type": "markdown",
            "max_length": 2000,
            "generation": {"mode": "manual"},
        },
    ]
    return fields


def _render(language: str, *, urgent: bool) -> str:
    fr = language == "fr"
    labels = {
        "severity": "Sévérité" if fr else "Severity",
        "summary": "Résumé" if fr else "Summary",
        "products": "Produits concernés" if fr else "Affected products",
        "exploitation": "Exploitation",
        "recommendations": "Recommandations" if fr else "Recommendations",
        "references": "Références" if fr else "References",
        "note": "Note de l'analyste" if fr else "Analyst note",
    }
    banner = (
        ("> **Action urgente recommandée.**\n\n" if fr else "> **Urgent action recommended.**\n\n")
        if urgent
        else ""
    )
    return (
        "# {{ fields.title }}\n\n"
        f"{banner}"
        "{{ tlp | tlp_label }}"
        f" — **{labels['severity']}** : "
        '{{ fields.severity | severity_label: language | default: "—" }}'
        "{% if fields.cvss %} — **CVSS** : {{ fields.cvss.score }} "
        "({{ fields.cvss.vector }}){% endif %}"
        '{% if fields.cves.size > 0 %} — **CVE** : {{ fields.cves | join: ", " }}{% endif %}\n\n'
        f"## {labels['summary']}\n\n{{{{ fields.summary }}}}\n\n"
        "{% if fields.affected_products.size > 0 %}"
        f"## {labels['products']}\n\n"
        "{% for p in fields.affected_products %}- {{ p.vendor }} {{ p.product }}"
        "{% if p.versions != blank %} ({{ p.versions }}){% endif %}\n{% endfor %}\n"
        "{% endif %}"
        "{% if fields.exploitation != blank %}"
        f"## {labels['exploitation']}\n\n{{{{ fields.exploitation }}}}\n\n"
        "{% endif %}"
        f"## {labels['recommendations']}\n\n{{{{ fields.recommendations }}}}\n\n"
        "{% if fields.analyst_note != blank %}"
        f"## {labels['note']}\n\n{{{{ fields.analyst_note }}}}\n\n"
        "{% endif %}"
        "{% if fields.references.size > 0 %}"
        f"## {labels['references']}\n\n"
        "{% for r in fields.references %}- [{{ r.title }}]({{ r.url }})\n{% endfor %}"
        "{% endif %}"
    )


def _spec(language: str, *, urgent: bool) -> dict[str, Any]:
    fr = language == "fr"
    spec: dict[str, Any] = {
        "language": language,
        "priority": 100 if urgent else 0,
        "tlp": "AMBER",
        "match_rules": [
            {"kev": True},
            {"exploitation_in": ["exploited_itw"]},
            {"severity_min": "critical"},
        ]
        if urgent
        else [],
        "style_guide": (
            "Ton factuel, phrases courtes, pas de spéculation. Toujours citer les sources. "
            "Écrire pour des équipes techniques et des responsables sécurité."
            if fr
            else "Factual tone, short sentences, no speculation. Always cite sources. "
            "Write for technical teams and security managers."
        ),
        "example": "",
        "fields": _fields(language, urgent=urgent),
        "render_template": _render(language, urgent=urgent),
    }
    parse_spec(spec)  # delivered templates are valid by construction
    return spec


SEEDS: dict[str, tuple[str, str, dict[str, Any]]] = {
    "generic_fr": (
        "Bulletin générique (FR)",
        "Modèle par défaut : utilisé quand aucune règle d'un autre modèle ne s'applique.",
        _spec("fr", urgent=False),
    ),
    "generic_en": (
        "Generic bulletin (EN)",
        "Default English template.",
        _spec("en", urgent=False),
    ),
    "urgent_fr": (
        "Vulnérabilité exploitée ou critique (FR)",
        "Prioritaire : CVE du catalogue KEV, exploitée dans la nature, ou de sévérité critique.",
        _spec("fr", urgent=True),
    ),
}


async def seed_templates(
    db: AsyncSession, workspace_id: uuid.UUID, slug: str, now: datetime
) -> list[str]:
    """Creates the missing delivered templates and the bulletin settings of a workspace
    (app role, workspace context). Existing templates are left as analysts made them."""
    existing: dict[str | None, uuid.UUID] = dict(
        (
            await db.execute(
                select(BulletinTemplate.seed_key, BulletinTemplate.id).where(
                    BulletinTemplate.workspace_id == workspace_id,
                    BulletinTemplate.seed_key.is_not(None),
                )
            )
        ).all()
    )
    created: list[str] = []
    for key, (name, description, spec) in SEEDS.items():
        if key in existing:
            continue
        template = BulletinTemplate(
            id=uuid7(),
            workspace_id=workspace_id,
            name=name,
            description=description,
            status="active",
            seed_key=key,
            created_at=now,
            updated_at=now,
        )
        db.add(template)
        await db.flush()
        version = BulletinTemplateVersion(
            id=uuid7(),
            workspace_id=workspace_id,
            template_id=template.id,
            version_no=1,
            spec=spec,
            language=spec["language"],
            priority=spec["priority"],
            comment="Version livrée",
            created_at=now,
        )
        db.add(version)
        await db.flush()
        template.active_version_id = version.id
        existing[key] = template.id
        created.append(f"template:{key}")
    if await db.get(BulletinSettings, workspace_id) is None:
        prefix = "".join(c for c in slug.upper() if c.isalnum() or c == "-")[:16] or "BUL"
        db.add(
            BulletinSettings(
                workspace_id=workspace_id,
                ref_prefix=prefix if prefix[0].isalpha() else f"B{prefix}"[:16],
                default_template_id=existing.get("generic_fr"),
                updated_at=now,
            )
        )
    await db.flush()
    return created
