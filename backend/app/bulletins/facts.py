"""What a bulletin knows about a vulnerability, seen from one workspace.

Catalogue data (NVD, KEV, EPSS), the workspace's own qualification, the matched
technologies, the evidence collected by the workspace and its latest AI synthesis. The
same facts drive template matching (selection.py) and computed fields; collected
content stays data, bounded, and is never rendered as a template.
"""

import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.models import CveRecord
from app.catalog.nvd_parse import CVSS_KEYS
from app.technologies.models import Technology
from app.vulns.models import (
    Analysis,
    Assessment,
    Evidence,
    Vulnerability,
    VulnerabilityTechnology,
)
from app.watch.models import CollectedItem

MAX_REFERENCES = 30
MAX_TEXT = 4000


@dataclass
class Facts:
    vulnerability_id: uuid.UUID | None
    severity: str | None = None
    kev: bool = False
    exploitation_status: str = "unknown"
    priority: str | None = None
    cwes: list[str] = field(default_factory=list)
    epss: float | None = None
    technologies: list[tuple[str, str]] = field(default_factory=list)  # (vendor, product)
    # Computed sources (spec.COMPUTED_SOURCES) to their values.
    values: dict[str, Any] = field(default_factory=dict)


def _num(value: Decimal | None) -> float | None:
    return float(value) if value is not None else None


def _cvss(record: CveRecord | None) -> dict[str, Any] | None:
    if record is None:
        return None
    for _, key in CVSS_KEYS:
        metrics = [m for m in record.cvss.get(key, []) if m.get("score") is not None]
        if metrics:
            best = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
            return {
                "score": best["score"],
                "vector": best.get("vector", ""),
                "version": best.get("version", ""),
                "severity": (best.get("severity") or "").lower() or None,
            }
    return None


async def vulnerability_facts(
    db: AsyncSession, workspace_id: uuid.UUID, vulnerability_id: uuid.UUID
) -> Facts | None:
    vuln = await db.get(Vulnerability, vulnerability_id)
    if vuln is None:
        return None
    record = await db.get(CveRecord, vuln.cve_id) if vuln.cve_id else None
    assessment = (
        await db.execute(
            select(Assessment).where(
                Assessment.vulnerability_id == vuln.id, Assessment.workspace_id == workspace_id
            )
        )
    ).scalar_one_or_none()
    technologies = (
        await db.execute(
            select(Technology.vendor, Technology.product, Technology.display_name)
            .join(VulnerabilityTechnology, VulnerabilityTechnology.technology_id == Technology.id)
            .where(VulnerabilityTechnology.vulnerability_id == vuln.id)
            .order_by(Technology.display_name)
        )
    ).all()
    references = (
        await db.execute(
            select(CollectedItem.title, CollectedItem.url, Evidence.kind)
            .join(Evidence, Evidence.collected_item_id == CollectedItem.id)
            .where(Evidence.vulnerability_id == vuln.id, Evidence.workspace_id == workspace_id)
            .order_by(Evidence.created_at)
            .limit(MAX_REFERENCES)
        )
    ).all()
    synthesis = (
        await db.execute(
            select(Analysis.content)
            .where(Analysis.vulnerability_id == vuln.id, Analysis.workspace_id == workspace_id)
            .order_by(Analysis.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none() or {}

    severity = (
        (assessment.severity if assessment and assessment.severity else None)
        or (record.severity if record else None)
        or ""
    ).lower() or None
    if severity == "none":
        severity = None
    cve_ids = [i for i in [vuln.cve_id, *vuln.aliases] if i and i.startswith("CVE-")]
    refs = [
        {"title": (t or u or "")[:300], "url": u}
        for t, u, _ in references
        if u and u.lower().startswith(("https://", "http://"))
    ]
    if record:
        known = {r["url"] for r in refs}
        refs += [
            {"title": r["url"], "url": r["url"]}
            for r in record.references[: MAX_REFERENCES - len(refs)]
            if str(r.get("url") or "").lower().startswith(("https://", "http://"))
            and r["url"] not in known
        ]
    facts = Facts(
        vulnerability_id=vuln.id,
        severity=severity,
        kev=bool(record and record.kev),
        exploitation_status=vuln.exploitation_status,
        priority=assessment.priority if assessment else None,
        cwes=list(record.cwes) if record else [],
        epss=_num(record.epss_score) if record else None,
        technologies=[(v, p) for v, p, _ in technologies],
    )
    facts.values = {
        "vuln.ref": vuln.ref,
        "vuln.title": vuln.title,
        "vuln.description": (record.description if record else vuln.summary)[:MAX_TEXT],
        "vuln.cve_ids": cve_ids,
        "vuln.severity": severity,
        "vuln.cvss": _cvss(record),
        "vuln.kev": facts.kev,
        "vuln.kev_date_added": (record.kev or {}).get("date_added") if record else None,
        "vuln.epss": f"{facts.epss:.2%}" if facts.epss is not None else None,
        "vuln.exploitation_status": vuln.exploitation_status,
        "vuln.patch_status": vuln.patch_status,
        "vuln.priority": facts.priority,
        "vuln.cwes": facts.cwes,
        "vuln.technologies": [name for _, _, name in technologies],
        "vuln.published_at": record.published_at.date().isoformat()
        if record and record.published_at
        else None,
        "evidence.references": refs[:MAX_REFERENCES],
        "synthesis.summary": str(synthesis.get("summary") or "")[:MAX_TEXT] or None,
        "synthesis.affected_products": [
            {k: str(p.get(k) or "")[:200] for k in ("vendor", "product", "versions")}
            for p in synthesis.get("affected_products") or []
            if isinstance(p, dict)
        ][:50],
        "synthesis.mitigations": [
            str(m.get("text") if isinstance(m, dict) else m)[:1000]
            for m in synthesis.get("mitigations") or []
        ][:30],
    }
    return facts
