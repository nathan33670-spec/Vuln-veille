"""Vulnerability API (ADR-024).

- Reading (``vuln.read``, every internal user): the shared record with every team's
  assessment, technologies, evidence, AI analyses and timeline.
- Writing, under ``/workspaces/{workspace}`` (``vuln.qualify``): create or promote,
  shared fields, the team's own assessment, adopting the other team's, private
  comments, technology links and evidence. Each write is audited.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.catalog.models import CveRecord
from app.core.tasks import TaskQueue
from app.iam.deps import DB, WorkspaceAccess, require, require_workspace
from app.iam.models import Workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.technologies.models import Technology
from app.vulns.models import (
    Analysis,
    Assessment,
    Comment,
    Evidence,
    Vulnerability,
    VulnerabilityEvent,
    VulnerabilityTechnology,
)
from app.vulns.schemas import (
    AdoptIn,
    AnalysisOut,
    AssessmentIn,
    AssessmentOut,
    CommentIn,
    CommentOut,
    CveOut,
    EvidenceIn,
    EvidenceOut,
    TechnologyLinkOut,
    TimelineEventOut,
    VulnerabilityCreate,
    VulnerabilityDetailOut,
    VulnerabilityPage,
    VulnerabilitySummaryOut,
    VulnerabilityUpdate,
)
from app.vulns.service import (
    UNQUALIFIED,
    adopt_assessment,
    create_vulnerability,
    event,
    get_by_ref,
    update_assessment,
)
from app.watch.collect import store_item
from app.watch.models import CollectedItem

Reader = Annotated[Principal, Depends(require(Permission.VULN_READ))]
Qualifier = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.VULN_QUALIFY))]
CVE_FETCH_TASK = "collect.cve_fetch"
TIMELINE_LIMIT = 300


def now() -> datetime:
    return datetime.now(UTC)


async def workspace_slugs(db: AsyncSession) -> dict[uuid.UUID, str]:
    return {w.id: w.slug for w in (await db.execute(select(Workspace))).scalars()}


def cve_out(cve: CveRecord, ref: str | None = None) -> CveOut:
    return CveOut(
        cve_id=cve.cve_id,
        published_at=cve.published_at,
        last_modified_at=cve.last_modified_at,
        vuln_status=cve.vuln_status,
        description=cve.description,
        severity=cve.severity,
        base_score=cve.base_score,
        cvss=cve.cvss,
        cwes=cve.cwes,
        references=cve.references,
        cpe_criteria=cve.cpe_criteria,
        kev=cve.kev,
        epss_score=cve.epss_score,
        epss_percentile=cve.epss_percentile,
        sources=cve.sources,
        first_seen_at=cve.first_seen_at,
        vulnerability_ref=ref,
    )


def assessment_out(
    a: Assessment, slugs: dict[uuid.UUID, str], by_id: dict[uuid.UUID, Assessment]
) -> AssessmentOut:
    source = by_id.get(a.copied_from_assessment_id) if a.copied_from_assessment_id else None
    return AssessmentOut(
        id=a.id,
        workspace=slugs.get(a.workspace_id, "?"),
        status=a.status,
        priority=a.priority,
        severity=a.severity,
        assignee_id=a.assignee_id,
        rationale=a.rationale,
        qualified_at=a.qualified_at,
        qualified_by=a.qualified_by,
        adopted_from=slugs.get(source.workspace_id) if source else None,
        version=a.version,
        updated_at=a.updated_at,
    )


async def _assessments(db: AsyncSession, ids: list[uuid.UUID]) -> dict[uuid.UUID, list[Assessment]]:
    rows = await db.execute(select(Assessment).where(Assessment.vulnerability_id.in_(ids)))
    found: dict[uuid.UUID, list[Assessment]] = {}
    for a in rows.scalars():
        found.setdefault(a.vulnerability_id, []).append(a)
    return found


def summary_out(
    v: Vulnerability,
    cve: CveRecord | None,
    assessments: list[Assessment],
    slugs: dict[uuid.UUID, str],
) -> VulnerabilitySummaryOut:
    by_id = {a.id: a for a in assessments}
    return VulnerabilitySummaryOut(
        id=v.id,
        ref=v.ref,
        cve_id=v.cve_id,
        title=v.title,
        severity=cve.severity if cve else None,
        base_score=cve.base_score if cve else None,
        kev=bool(cve and cve.kev),
        epss_score=cve.epss_score if cve else None,
        exploitation_status=v.exploitation_status,
        patch_status=v.patch_status,
        first_seen_at=v.first_seen_at,
        assessments=sorted(
            (assessment_out(a, slugs, by_id) for a in assessments), key=lambda a: a.workspace
        ),
    )


async def detail_out(db: AsyncSession, v: Vulnerability) -> VulnerabilityDetailOut:
    slugs = await workspace_slugs(db)
    cve = await db.get(CveRecord, v.cve_id) if v.cve_id else None
    assessments = (await _assessments(db, [v.id])).get(v.id, [])
    summary = summary_out(v, cve, assessments, slugs)
    techs = await db.execute(
        select(VulnerabilityTechnology, Technology)
        .join(Technology, Technology.id == VulnerabilityTechnology.technology_id)
        .where(VulnerabilityTechnology.vulnerability_id == v.id)
    )
    evidence = await db.execute(
        select(Evidence, CollectedItem)
        .join(CollectedItem, CollectedItem.id == Evidence.collected_item_id)
        .where(Evidence.vulnerability_id == v.id)
        .order_by(Evidence.created_at)
    )
    analyses = await db.execute(
        select(Analysis)
        .where(Analysis.vulnerability_id == v.id)
        .order_by(Analysis.created_at.desc())
        .limit(20)
    )
    timeline = await db.execute(
        select(VulnerabilityEvent)
        .where(VulnerabilityEvent.vulnerability_id == v.id)
        .order_by(VulnerabilityEvent.occurred_at, VulnerabilityEvent.id)
        .limit(TIMELINE_LIMIT)
    )
    duplicate = await db.get(Vulnerability, v.duplicate_of) if v.duplicate_of else None
    return VulnerabilityDetailOut(
        **summary.model_dump(),
        summary=v.summary,
        aliases=v.aliases,
        origin=v.origin,
        version=v.version,
        duplicate_of_ref=duplicate.ref if duplicate else None,
        cve=cve_out(cve, v.ref) if cve else None,
        technologies=[
            TechnologyLinkOut(
                technology_id=t.id,
                display_name=t.display_name,
                vendor=t.vendor,
                product=t.product,
                matched_by=link.matched_by,
            )
            for link, t in techs.all()
        ],
        evidence=[
            EvidenceOut(
                id=e.id,
                kind=e.kind,
                note=e.note,
                workspace=slugs.get(e.workspace_id, "?"),
                added_by_type=e.added_by_type,
                created_at=e.created_at,
                url=item.url,
                title=item.title,
                source_type=item.source_type,
                trust=item.trust,
            )
            for e, item in evidence.all()
        ],
        analyses=[
            AnalysisOut(
                id=a.id,
                workspace=slugs.get(a.workspace_id, "?"),
                content=a.content,
                injection_flags=a.injection_flags,
                created_at=a.created_at,
            )
            for a in analyses.scalars()
        ],
        timeline=[
            TimelineEventOut(
                type=e.type,
                workspace=slugs.get(e.workspace_id) if e.workspace_id else None,
                actor_type=e.actor_type,
                actor_user_id=e.actor_user_id,
                data=e.data,
                occurred_at=e.occurred_at,
            )
            for e in timeline.scalars()
        ],
    )


async def _audit(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    action: str,
    v: Vulnerability,
    **details: object,
) -> None:
    await record(
        db,
        access.principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="vulnerability",
            target_id=v.ref,
            workspace_id=access.workspace.id,
            details=details,
        ),
    )


def _filtered(
    q: str | None,
    team_id: uuid.UUID | None,
    state: str,
    severity: str | None,
    kev: bool | None,
    priority: str | None,
    mine: uuid.UUID | None,
) -> Select[Vulnerability, CveRecord]:
    query = select(Vulnerability, CveRecord).outerjoin(
        CveRecord, CveRecord.cve_id == Vulnerability.cve_id
    )
    if team_id is not None:
        query = query.outerjoin(
            Assessment,
            and_(
                Assessment.vulnerability_id == Vulnerability.id, Assessment.workspace_id == team_id
            ),
        )
        if state == "unqualified":
            query = query.where(or_(Assessment.id.is_(None), Assessment.status.in_(UNQUALIFIED)))
        elif state != "all":
            query = query.where(Assessment.status == state)
        if priority:
            query = query.where(Assessment.priority == priority)
        if mine:
            query = query.where(Assessment.assignee_id == mine)
    if q:
        term = f"%{q.strip().replace('%', '').replace('_', '')}%"
        query = query.where(
            or_(
                Vulnerability.title.ilike(term),
                Vulnerability.cve_id.ilike(term),
                Vulnerability.ref.ilike(term),
            )
        )
    if severity:
        query = query.where(CveRecord.severity == severity)
    if kev is not None:
        query = query.where(CveRecord.kev.is_not(None) if kev else CveRecord.kev.is_(None))
    return query.where(Vulnerability.duplicate_of.is_(None))


def build_vulnerability_router() -> APIRouter:
    router = APIRouter(tags=["vulnerabilities"])

    @router.get("/vulnerabilities", response_model=VulnerabilityPage)
    async def list_vulnerabilities(
        principal: Reader,
        db: DB,
        q: Annotated[str | None, Query(max_length=100)] = None,
        team: Annotated[str | None, Query(pattern=r"^[a-z][a-z0-9-]{1,31}$")] = None,
        state: Literal[
            "unqualified",
            "all",
            "new",
            "triage",
            "qualified",
            "rejected",
            "duplicate",
            "monitoring",
        ] = "all",
        severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        kev: bool | None = None,
        priority: Literal["P1", "P2", "P3", "P4"] | None = None,
        assigned_to_me: bool = False,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0, le=10000)] = 0,
    ) -> VulnerabilityPage:
        slugs = await workspace_slugs(db)
        team_id = next((i for i, s in slugs.items() if s == team), None)
        if team is not None and team_id is None:
            raise HTTPException(status_code=404, detail="not_found")
        query = _filtered(
            q,
            team_id,
            state,
            severity,
            kev,
            priority,
            principal.user_id if assigned_to_me else None,
        )
        total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        rows = (
            await db.execute(
                query.order_by(Vulnerability.first_seen_at.desc(), Vulnerability.id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        assessments = await _assessments(db, [v.id for v, _ in rows])
        return VulnerabilityPage(
            total=total,
            items=[summary_out(v, cve, assessments.get(v.id, []), slugs) for v, cve in rows],
        )

    @router.get("/vulnerabilities/{ref}", response_model=VulnerabilityDetailOut)
    async def get_vulnerability(ref: str, principal: Reader, db: DB) -> VulnerabilityDetailOut:
        return await detail_out(db, await get_by_ref(db, ref))

    base = "/workspaces/{workspace}/vulnerabilities"

    @router.post(base, response_model=VulnerabilityDetailOut, status_code=201)
    async def create(
        body: VulnerabilityCreate, request: Request, access: Qualifier, db: DB
    ) -> VulnerabilityDetailOut:
        when = now()
        vulnerability, created = await create_vulnerability(
            db,
            now=when,
            workspace_id=access.workspace.id,
            actor=access.principal.user_id,
            origin="user",
            cve_id=body.cve_id,
            title=body.title,
            summary=body.summary,
            aliases=body.aliases,
        )
        if not created:
            raise HTTPException(status_code=409, detail=f"exists:{vulnerability.ref}")
        await _audit(
            db, request, access, "vulnerability.created", vulnerability, cve_id=body.cve_id
        )
        await db.commit()
        if body.cve_id and await db.get(CveRecord, body.cve_id) is None:
            # Not in the catalogue yet: fetched from NVD by the collect worker.
            cast(TaskQueue, request.app.state.tasks).send(CVE_FETCH_TASK, {"cve_id": body.cve_id})
        return await detail_out(db, vulnerability)

    @router.patch(base + "/{ref}", response_model=VulnerabilityDetailOut)
    async def update(
        ref: str, body: VulnerabilityUpdate, request: Request, access: Qualifier, db: DB
    ) -> VulnerabilityDetailOut:
        vulnerability = await get_by_ref(db, ref)
        if body.version != vulnerability.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        changes = body.model_dump(exclude={"version", "duplicate_of_ref"}, exclude_none=True)
        if body.duplicate_of_ref is not None:
            target = await get_by_ref(db, body.duplicate_of_ref)
            if target.id == vulnerability.id:
                raise HTTPException(status_code=422, detail="self_duplicate")
            vulnerability.duplicate_of = target.id
            changes["duplicate_of"] = target.ref
        for field, value in changes.items():
            if field != "duplicate_of":
                setattr(vulnerability, field, value)
        if changes:
            vulnerability.version += 1
            event(
                db,
                vulnerability.id,
                "vulnerability.updated",
                now=now(),
                workspace_id=access.workspace.id,
                actor_user_id=access.principal.user_id,
                fields=sorted(changes),
            )
            await _audit(
                db, request, access, "vulnerability.updated", vulnerability, fields=sorted(changes)
            )
            await db.commit()
        return await detail_out(db, vulnerability)

    @router.put(base + "/{ref}/assessment", response_model=VulnerabilityDetailOut)
    async def assess(
        ref: str, body: AssessmentIn, request: Request, access: Qualifier, db: DB
    ) -> VulnerabilityDetailOut:
        vulnerability = await get_by_ref(db, ref)
        changes = body.model_dump(exclude={"version"}, exclude_unset=True)
        assessment = await update_assessment(
            db,
            vulnerability,
            access.workspace.id,
            changes,
            version=body.version,
            actor=access.principal.user_id,
            now=now(),
        )
        await _audit(
            db,
            request,
            access,
            "assessment.updated",
            vulnerability,
            status=assessment.status,
            priority=assessment.priority,
            fields=sorted(changes),
        )
        await db.commit()
        return await detail_out(db, vulnerability)

    @router.post(base + "/{ref}/assessment/adopt", response_model=VulnerabilityDetailOut)
    async def adopt(
        ref: str, body: AdoptIn, request: Request, access: Qualifier, db: DB
    ) -> VulnerabilityDetailOut:
        vulnerability = await get_by_ref(db, ref)
        slugs = await workspace_slugs(db)
        source_ws = next((i for i, s in slugs.items() if s == body.from_workspace), None)
        source = (
            (
                await db.execute(
                    select(Assessment).where(
                        Assessment.vulnerability_id == vulnerability.id,
                        Assessment.workspace_id == source_ws,
                    )
                )
            ).scalar_one_or_none()
            if source_ws
            else None
        )
        if source is None:
            raise HTTPException(status_code=404, detail="not_found")
        await adopt_assessment(
            db,
            vulnerability,
            access.workspace.id,
            source,
            actor=access.principal.user_id,
            now=now(),
        )
        await _audit(
            db,
            request,
            access,
            "assessment.adopted",
            vulnerability,
            from_workspace=body.from_workspace,
            status=source.status,
            priority=source.priority,
        )
        await db.commit()
        return await detail_out(db, vulnerability)

    @router.get(base + "/{ref}/comments", response_model=list[CommentOut])
    async def list_comments(ref: str, access: Qualifier, db: DB) -> list[CommentOut]:
        vulnerability = await get_by_ref(db, ref)
        rows = await db.execute(
            select(Comment)
            .where(
                Comment.vulnerability_id == vulnerability.id,
                Comment.workspace_id == access.workspace.id,
            )
            .order_by(Comment.created_at)
        )
        return [
            CommentOut(id=c.id, author_id=c.author_id, body=c.body, created_at=c.created_at)
            for c in rows.scalars()
        ]

    @router.post(base + "/{ref}/comments", response_model=CommentOut, status_code=201)
    async def add_comment(
        ref: str, body: CommentIn, request: Request, access: Qualifier, db: DB
    ) -> CommentOut:
        vulnerability = await get_by_ref(db, ref)
        comment = Comment(
            vulnerability_id=vulnerability.id,
            workspace_id=access.workspace.id,
            author_id=access.principal.user_id,
            body=body.body,
            created_at=now(),
        )
        db.add(comment)
        event(
            db,
            vulnerability.id,
            "comment.added",
            now=now(),
            workspace_id=access.workspace.id,
            actor_user_id=access.principal.user_id,
        )
        await _audit(db, request, access, "comment.added", vulnerability)
        await db.commit()
        return CommentOut(
            id=comment.id,
            author_id=comment.author_id,
            body=comment.body,
            created_at=comment.created_at,
        )

    @router.put(base + "/{ref}/technologies/{technology_id}", response_model=VulnerabilityDetailOut)
    async def link_technology(
        ref: str, technology_id: uuid.UUID, request: Request, access: Qualifier, db: DB
    ) -> VulnerabilityDetailOut:
        vulnerability = await get_by_ref(db, ref)
        technology = await db.get(Technology, technology_id)
        if technology is None or technology.status == "merged":
            raise HTTPException(status_code=404, detail="not_found")
        await db.execute(
            insert(VulnerabilityTechnology)
            .values(
                vulnerability_id=vulnerability.id,
                technology_id=technology.id,
                matched_by="manual",
            )
            .on_conflict_do_nothing()
        )
        event(
            db,
            vulnerability.id,
            "technology.linked",
            now=now(),
            workspace_id=access.workspace.id,
            actor_user_id=access.principal.user_id,
            technology=f"{technology.vendor}:{technology.product}",
        )
        await _audit(
            db,
            request,
            access,
            "vulnerability.technology_linked",
            vulnerability,
            technology_id=str(technology.id),
        )
        await db.commit()
        return await detail_out(db, vulnerability)

    @router.delete(base + "/{ref}/technologies/{technology_id}", status_code=204)
    async def unlink_technology(
        ref: str, technology_id: uuid.UUID, request: Request, access: Qualifier, db: DB
    ) -> None:
        vulnerability = await get_by_ref(db, ref)
        link = await db.get(VulnerabilityTechnology, (vulnerability.id, technology_id))
        if link is None:
            raise HTTPException(status_code=404, detail="not_found")
        await db.delete(link)
        event(
            db,
            vulnerability.id,
            "technology.unlinked",
            now=now(),
            workspace_id=access.workspace.id,
            actor_user_id=access.principal.user_id,
            technology_id=str(technology_id),
        )
        await _audit(
            db,
            request,
            access,
            "vulnerability.technology_unlinked",
            vulnerability,
            technology_id=str(technology_id),
        )
        await db.commit()

    @router.post(base + "/{ref}/evidence", response_model=VulnerabilityDetailOut, status_code=201)
    async def add_evidence(
        ref: str, body: EvidenceIn, request: Request, access: Qualifier, db: DB
    ) -> VulnerabilityDetailOut:
        """An analyst cites a link; it is stored as untrusted content, never fetched here."""
        vulnerability = await get_by_ref(db, ref)
        when = now()
        try:
            item, _ = await store_item(
                db,
                access.workspace.id,
                source_type="manual",
                now=when,
                url=str(body.url),
                title=body.title,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid_url") from exc
        await db.execute(
            insert(Evidence)
            .values(
                id=uuid.uuid4(),
                vulnerability_id=vulnerability.id,
                collected_item_id=item.id,
                kind=body.kind,
                note=body.note,
                added_by_type="user",
                added_by=access.principal.user_id,
                workspace_id=access.workspace.id,
                created_at=when,
            )
            .on_conflict_do_nothing()
        )
        event(
            db,
            vulnerability.id,
            "evidence.added",
            now=when,
            workspace_id=access.workspace.id,
            actor_user_id=access.principal.user_id,
            kind=body.kind,
        )
        await _audit(db, request, access, "evidence.added", vulnerability, kind=body.kind)
        await db.commit()
        return await detail_out(db, vulnerability)

    @router.delete(base + "/{ref}/evidence/{evidence_id}", status_code=204)
    async def remove_evidence(
        ref: str, evidence_id: uuid.UUID, request: Request, access: Qualifier, db: DB
    ) -> None:
        vulnerability = await get_by_ref(db, ref)
        evidence = await db.get(Evidence, evidence_id)
        if (
            evidence is None
            or evidence.vulnerability_id != vulnerability.id
            or evidence.workspace_id != access.workspace.id
        ):
            raise HTTPException(status_code=404, detail="not_found")
        await db.delete(evidence)
        event(
            db,
            vulnerability.id,
            "evidence.removed",
            now=now(),
            workspace_id=access.workspace.id,
            actor_user_id=access.principal.user_id,
        )
        await _audit(db, request, access, "evidence.removed", vulnerability)
        await db.commit()

    return router
