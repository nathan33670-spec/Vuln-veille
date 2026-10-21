"""Vulnerability records and team assessments (spec 01 §5, ADR-024).

One record per CVE (or per vulnerability without CVE), shared by both teams; each
team qualifies it in its own assessment. Every change is written to the timeline
(``vulnerability_events``); creation also emits ``vuln.created`` in the outbox.
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.models import CveRecord, OutboxEvent
from app.core.ids import uuid7
from app.iam.models import WorkspaceMembership
from app.technologies.models import Technology
from app.vulns.models import Assessment, Vulnerability, VulnerabilityEvent, VulnerabilityTechnology

TRANSITIONS: dict[str, frozenset[str]] = {
    "new": frozenset({"triage", "qualified", "rejected", "duplicate", "monitoring"}),
    "triage": frozenset({"qualified", "rejected", "duplicate", "monitoring"}),
    "monitoring": frozenset({"triage", "qualified", "rejected", "duplicate"}),
    "qualified": frozenset({"triage"}),
    "rejected": frozenset({"triage"}),
    "duplicate": frozenset({"triage"}),
}
UNQUALIFIED = ("new", "triage")
ASSESSMENT_FIELDS = ("status", "priority", "severity", "assignee_id", "rationale", "cvss_override")
TITLE_FROM_DESCRIPTION = 160


def event(
    db: AsyncSession,
    vulnerability_id: uuid.UUID,
    type_: str,
    *,
    now: datetime,
    workspace_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_type: str = "user",
    **data: Any,
) -> None:
    db.add(
        VulnerabilityEvent(
            vulnerability_id=vulnerability_id,
            workspace_id=workspace_id,
            type=type_,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            data=data,
            occurred_at=now,
        )
    )


def default_title(cve: CveRecord | None, cve_id: str) -> str:
    if cve is None or not cve.description:
        return cve_id
    text = " ".join(cve.description.split())
    short = text if len(text) <= TITLE_FROM_DESCRIPTION else text[:TITLE_FROM_DESCRIPTION] + "…"
    return f"{cve_id} : {short}"


async def link_technologies_by_cpe(
    db: AsyncSession, vulnerability: Vulnerability, cve: CveRecord | None
) -> list[uuid.UUID]:
    """Links the catalogue technologies whose CPE prefixes match the CVE's criteria."""
    if cve is None or not cve.cpe_criteria:
        return []
    rows = await db.execute(select(Technology).where(Technology.status == "active"))
    linked = [
        tech.id
        for tech in rows.scalars()
        if any(c.startswith(p) for p in tech.cpe_prefixes for c in cve.cpe_criteria)
    ]
    for technology_id in linked:
        await db.execute(
            insert(VulnerabilityTechnology)
            .values(
                vulnerability_id=vulnerability.id,
                technology_id=technology_id,
                matched_by="cpe",
                confidence=Decimal(1),
            )
            .on_conflict_do_nothing()
        )
    return linked


async def create_vulnerability(
    db: AsyncSession,
    *,
    now: datetime,
    workspace_id: uuid.UUID,
    actor: uuid.UUID | None,
    origin: str,
    cve_id: str | None = None,
    title: str | None = None,
    summary: str = "",
    aliases: list[str] | None = None,
) -> tuple[Vulnerability, bool]:
    """Returns the record and whether it was created (one record per CVE)."""
    cve = None
    if cve_id is not None:
        existing = (
            await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False
        cve = await db.get(CveRecord, cve_id)
    if not title and cve_id is None:
        raise HTTPException(status_code=422, detail="title_required")
    vulnerability = Vulnerability(
        id=uuid7(),
        cve_id=cve_id,
        aliases=sorted(set(aliases or [])),
        title=title or default_title(cve, cve_id or ""),
        summary=summary,
        first_seen_at=now,
        origin=origin,
        origin_workspace_id=workspace_id,
        created_by=actor,
        version=1,
    )
    db.add(vulnerability)
    await db.flush()
    await db.refresh(vulnerability, ["ref"])
    linked = await link_technologies_by_cpe(db, vulnerability, cve)
    event(
        db,
        vulnerability.id,
        "vulnerability.created",
        now=now,
        workspace_id=workspace_id,
        actor_user_id=actor,
        origin=origin,
        cve_id=cve_id,
        technologies=len(linked),
    )
    db.add(
        OutboxEvent(
            type="vuln.created",
            workspace_id=workspace_id,
            created_at=now,
            attempts=0,
            payload={
                "vulnerability_id": str(vulnerability.id),
                "ref": vulnerability.ref,
                "cve_id": cve_id,
                "origin": origin,
            },
        )
    )
    return vulnerability, True


async def get_by_ref(db: AsyncSession, ref: str) -> Vulnerability:
    vulnerability = (
        await db.execute(select(Vulnerability).where(Vulnerability.ref == ref))
    ).scalar_one_or_none()
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="not_found")
    return vulnerability


async def team_assessment(
    db: AsyncSession, vulnerability_id: uuid.UUID, workspace_id: uuid.UUID
) -> Assessment | None:
    return (
        await db.execute(
            select(Assessment)
            .where(
                Assessment.vulnerability_id == vulnerability_id,
                Assessment.workspace_id == workspace_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()


async def _check_assignee(db: AsyncSession, workspace_id: uuid.UUID, user_id: uuid.UUID) -> None:
    membership = await db.get(WorkspaceMembership, (user_id, workspace_id))
    if membership is None or membership.role != "analyst":
        raise HTTPException(status_code=422, detail="assignee_not_analyst")


async def update_assessment(
    db: AsyncSession,
    vulnerability: Vulnerability,
    workspace_id: uuid.UUID,
    changes: dict[str, Any],
    *,
    version: int,
    actor: uuid.UUID,
    now: datetime,
) -> Assessment:
    assessment = await team_assessment(db, vulnerability.id, workspace_id)
    if (assessment.version if assessment else 0) != version:
        raise HTTPException(status_code=409, detail="version_conflict")
    if assessment is None:
        assessment = Assessment(
            id=uuid7(),
            vulnerability_id=vulnerability.id,
            workspace_id=workspace_id,
            status="new",
            rationale="",
            version=0,
        )
        db.add(assessment)
    previous = assessment.status
    target = changes.get("status", previous)
    if target != previous and target not in TRANSITIONS[previous]:
        raise HTTPException(status_code=409, detail="invalid_transition")
    if changes.get("assignee_id"):
        await _check_assignee(db, workspace_id, changes["assignee_id"])
    for field in ASSESSMENT_FIELDS:
        if field in changes:
            setattr(assessment, field, changes[field])
    if target == "qualified" and not assessment.priority:
        raise HTTPException(status_code=422, detail="priority_required")
    if target == "duplicate" and vulnerability.duplicate_of is None:
        raise HTTPException(status_code=422, detail="duplicate_of_required")
    if target == "qualified" and previous != "qualified":
        assessment.qualified_at, assessment.qualified_by = now, actor
    assessment.copied_from_assessment_id = None
    assessment.version += 1
    await db.flush()
    event(
        db,
        vulnerability.id,
        "assessment.updated",
        now=now,
        workspace_id=workspace_id,
        actor_user_id=actor,
        fields=sorted(changes),
        status=assessment.status,
        priority=assessment.priority,
    )
    return assessment


async def adopt_assessment(
    db: AsyncSession,
    vulnerability: Vulnerability,
    workspace_id: uuid.UUID,
    source: Assessment,
    *,
    actor: uuid.UUID,
    now: datetime,
) -> Assessment:
    """« Reprendre cette qualification » : copies the other team's qualification."""
    if source.workspace_id == workspace_id or source.vulnerability_id != vulnerability.id:
        raise HTTPException(status_code=422, detail="invalid_source")
    assessment = await team_assessment(db, vulnerability.id, workspace_id)
    if assessment is None:
        assessment = Assessment(
            id=uuid7(),
            vulnerability_id=vulnerability.id,
            workspace_id=workspace_id,
            status="new",
            rationale="",
            version=0,
        )
        db.add(assessment)
    for field in ("status", "priority", "severity", "rationale", "cvss_override"):
        setattr(assessment, field, getattr(source, field))
    if source.status == "qualified":
        assessment.qualified_at, assessment.qualified_by = now, actor
    assessment.copied_from_assessment_id = source.id
    assessment.version += 1
    await db.flush()
    event(
        db,
        vulnerability.id,
        "assessment.adopted",
        now=now,
        workspace_id=workspace_id,
        actor_user_id=actor,
        from_workspace_id=str(source.workspace_id),
        status=assessment.status,
        priority=assessment.priority,
    )
    return assessment
