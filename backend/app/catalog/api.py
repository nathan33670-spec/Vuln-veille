"""CVE catalogue API (``vuln.read``): NVD news, search, scope decisions, sync status.

``scope_of`` evaluates each listed CVE against a team's watch scope; only members of
that team may use it (the scope itself is private to the workspace).
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, or_, select

from app.catalog.models import CveChange, CveRecord
from app.connectors.base import registered
from app.connectors.models import Connector, ConnectorCursor
from app.core.rls import get_context, set_context
from app.iam.deps import DB, require
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.vulns.api import cve_out
from app.vulns.models import Vulnerability
from app.vulns.schemas import CveChangeOut, CveDetailOut, CvePage, SyncStatusOut
from app.watch.scope import load_scope, match, scope_technologies

Reader = Annotated[Principal, Depends(require(Permission.VULN_READ))]
MAX_SCOPE_WINDOW = 2000


def build_catalog_router() -> APIRouter:
    router = APIRouter(prefix="/cves", tags=["catalogue"])

    @router.get("", response_model=CvePage)
    async def list_cves(
        principal: Reader,
        db: DB,
        q: Annotated[str | None, Query(max_length=100)] = None,
        since_days: Annotated[int, Query(ge=1, le=3650)] = 7,
        severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        kev: bool | None = None,
        scope_of: Annotated[str | None, Query(pattern=r"^[a-z][a-z0-9-]{1,31}$")] = None,
        decision: Literal["in_scope", "out_of_scope", "pending"] | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0, le=10000)] = 0,
    ) -> CvePage:
        query = (
            select(CveRecord, Vulnerability.ref)
            .outerjoin(Vulnerability, Vulnerability.cve_id == CveRecord.cve_id)
            .where(CveRecord.first_seen_at >= datetime.now(UTC) - timedelta(days=since_days))
        )
        if q:
            term = f"%{q.strip().replace('%', '').replace('_', '')}%"
            query = query.where(
                or_(CveRecord.cve_id.ilike(term), CveRecord.description.ilike(term))
            )
        if severity:
            query = query.where(CveRecord.severity == severity)
        if kev is not None:
            query = query.where(CveRecord.kev.is_not(None) if kev else CveRecord.kev.is_(None))
        query = query.order_by(CveRecord.published_at.desc().nulls_last(), CveRecord.cve_id)

        if scope_of is None:
            if decision is not None:
                raise HTTPException(status_code=422, detail="scope_of_required")
            total = (
                await db.execute(select(func.count()).select_from(query.subquery()))
            ).scalar_one()
            rows = (await db.execute(query.limit(limit).offset(offset))).all()
            return CvePage(total=total, items=[cve_out(c, ref) for c, ref in rows])

        grant = principal.grants.workspaces.get(scope_of)
        if grant is None:
            raise HTTPException(status_code=404, detail="not_found")
        scope = await load_scope(db, grant.id)  # RLS: the caller is a member of this team
        technologies = await scope_technologies(db, scope)
        evaluated = []
        for cve, ref in (await db.execute(query.limit(MAX_SCOPE_WINDOW))).all():
            verdict = match(scope, cve, technologies)
            if decision is None or verdict.decision == decision:
                item = cve_out(cve, ref)
                item.scope_decision, item.scope_reasons = verdict.decision, verdict.reasons
                evaluated.append(item)
        return CvePage(total=len(evaluated), items=evaluated[offset : offset + limit])

    @router.get("/sync-status", response_model=list[SyncStatusOut])
    async def sync_status(principal: Reader, db: DB) -> list[SyncStatusOut]:
        """Health of the global catalogue sources (last success, delay, errors)."""
        # Global connectors are visible to administrators only (RLS); this read-only view
        # exposes their sync health to every analyst, then restores the request context.
        previous = get_context(db).is_platform_admin
        await set_context(db, is_platform_admin=True)
        try:
            synced = [kind for kind, t in registered().items() if t.syncs]
            connectors = list(
                (
                    await db.execute(
                        select(Connector)
                        .where(Connector.workspace_id.is_(None), Connector.kind.in_(synced))
                        .order_by(Connector.kind)
                    )
                ).scalars()
            )
            cursors = list(
                (
                    await db.execute(
                        select(ConnectorCursor).where(
                            ConnectorCursor.connector_id.in_([c.id for c in connectors])
                        )
                    )
                ).scalars()
            )
        finally:
            await set_context(db, is_platform_admin=previous)
        out = []
        for connector in connectors:
            position = {c.stream: c.position for c in cursors if c.connector_id == connector.id}
            out.append(
                SyncStatusOut(
                    kind=connector.kind,
                    name=connector.name,
                    enabled=connector.enabled,
                    last_success_at=connector.last_success_at,
                    last_check_at=connector.last_check_at,
                    last_error=connector.last_error,
                    consecutive_failures=connector.consecutive_failures,
                    position=position,
                )
            )
        return out

    @router.get("/{cve_id}", response_model=CveDetailOut)
    async def get_cve(
        cve_id: Annotated[str, Path(pattern=r"^CVE-\d{4}-\d{4,19}$")],
        principal: Reader,
        db: DB,
    ) -> CveDetailOut:
        cve = await db.get(CveRecord, cve_id)
        if cve is None:
            raise HTTPException(status_code=404, detail="not_found")
        ref = (
            await db.execute(select(Vulnerability.ref).where(Vulnerability.cve_id == cve_id))
        ).scalar_one_or_none()
        changes = await db.execute(
            select(CveChange).where(CveChange.cve_id == cve_id).order_by(CveChange.detected_at)
        )
        return CveDetailOut(
            **cve_out(cve, ref).model_dump(),
            changes=[
                CveChangeOut(
                    detected_at=c.detected_at,
                    change_types=c.change_types,
                    source=c.source,
                    diff=c.diff,
                )
                for c in changes.scalars()
            ],
        )

    return router
