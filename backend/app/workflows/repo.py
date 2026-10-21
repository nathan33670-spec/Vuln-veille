"""Workspace-scoped data access for nodes (spec 02 §4: no direct SQL session).

Every method works inside the node task's transaction, whose RLS context holds the
run's workspace only; queries are also filtered by ``workspace_id`` in code.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.models import CveRecord
from app.iam.models import User, WorkspaceMembership
from app.technologies.models import Technology
from app.vulns.models import Assessment, Evidence, Vulnerability
from app.vulns.service import UNQUALIFIED, create_vulnerability, event, link_technologies_by_cpe
from app.watch.collect import store_item
from app.watch.models import WatchScope
from app.watch.scope import load_scope, scope_technologies
from app.workflows.models import DedupeKey

KEV_EXPLOITED = "exploited_itw"


def _num(value: Decimal | None) -> float | None:
    return float(value) if value is not None else None


def cve_summary(cve: CveRecord) -> dict[str, Any]:
    """The CVE fields nodes and expressions see (catalogue data, from NVD)."""
    return {
        "cve_id": cve.cve_id,
        "published_at": cve.published_at.isoformat() if cve.published_at else None,
        "status": cve.vuln_status,
        "description": cve.description[:4000],
        "base_score": _num(cve.base_score),
        "severity": cve.severity,
        "cwes": list(cve.cwes),
        "cpe_criteria": list(cve.cpe_criteria)[:200],
        "kev": cve.kev is not None,
        "kev_date_added": (cve.kev or {}).get("date_added"),
        "epss_score": _num(cve.epss_score),
        "epss_percentile": _num(cve.epss_percentile),
    }


@dataclass
class WorkspaceRepo:
    db: AsyncSession
    workspace_id: uuid.UUID
    now: datetime
    run_id: uuid.UUID | None = None
    node_id: str | None = None

    # Catalogue (global, read-only) -------------------------------------------------

    async def cve(self, cve_id: str) -> CveRecord | None:
        return await self.db.get(CveRecord, cve_id)

    async def search_cves(
        self,
        *,
        published_since: datetime | None,
        min_score: float | None,
        kev_only: bool,
        kev_added_since: datetime | None,
        keyword: str | None,
        limit: int,
    ) -> list[CveRecord]:
        query = select(CveRecord).where(
            or_(CveRecord.vuln_status.is_(None), CveRecord.vuln_status != "Rejected")
        )
        if published_since is not None:
            query = query.where(CveRecord.published_at >= published_since)
        if min_score is not None:
            query = query.where(CveRecord.base_score >= Decimal(str(min_score)))
        if kev_only or kev_added_since is not None:
            query = query.where(CveRecord.kev.is_not(None))
        if kev_added_since is not None:
            query = query.where(
                CveRecord.kev["date_added"].astext >= kev_added_since.date().isoformat()
            )
        if keyword:
            term = "%" + keyword.replace("%", "").replace("_", "") + "%"
            query = query.where(CveRecord.description.ilike(term))
        rows = await self.db.execute(
            query.order_by(CveRecord.published_at.desc().nulls_last()).limit(limit)
        )
        return list(rows.scalars())

    # Watch scope ----------------------------------------------------------------

    async def scope(self) -> tuple[WatchScope, list[Technology]]:
        """The workspace's watch scope and its followed technologies (merges resolved)."""
        scope = await load_scope(self.db, self.workspace_id)
        return scope, await scope_technologies(self.db, scope)

    # Vulnerabilities (shared records, team assessments: ADR-024) -------------------

    async def upsert_vulnerability(self, cve_id: str) -> tuple[Vulnerability, bool]:
        """One record per CVE; the team's assessment is opened as ``new``."""
        vulnerability, created = await create_vulnerability(
            self.db,
            now=self.now,
            workspace_id=self.workspace_id,
            actor=None,
            origin="workflow",
            cve_id=cve_id,
        )
        opened = await self.db.execute(
            insert(Assessment)
            .values(
                id=uuid.uuid4(),
                vulnerability_id=vulnerability.id,
                workspace_id=self.workspace_id,
                status="new",
                rationale="",
                version=1,
            )
            .on_conflict_do_nothing(constraint="uq_assessments_team")
            .returning(Assessment.id)
        )
        if opened.scalar_one_or_none() is not None and not created:
            event(
                self.db,
                vulnerability.id,
                "workflow.matched",
                now=self.now,
                workspace_id=self.workspace_id,
                actor_type="workflow",
                run_id=str(self.run_id) if self.run_id else None,
            )
        return vulnerability, created

    async def vulnerability(self, vulnerability_id: uuid.UUID) -> Vulnerability | None:
        return await self.db.get(Vulnerability, vulnerability_id)

    async def mark_exploited(self, vulnerability: Vulnerability, reason: str) -> bool:
        if vulnerability.exploitation_status in (KEV_EXPLOITED, "not_exploitable"):
            return False
        vulnerability.exploitation_status = KEV_EXPLOITED
        vulnerability.version += 1
        event(
            self.db,
            vulnerability.id,
            "vulnerability.updated",
            now=self.now,
            workspace_id=self.workspace_id,
            actor_type="workflow",
            fields=["exploitation_status"],
            reason=reason,
        )
        return True

    async def link_technologies(
        self, vulnerability: Vulnerability, cve: CveRecord | None
    ) -> list[Technology]:
        linked = await link_technologies_by_cpe(self.db, vulnerability, cve)
        if not linked:
            return []
        rows = await self.db.execute(select(Technology).where(Technology.id.in_(linked)))
        return list(rows.scalars())

    async def list_vulnerabilities(
        self, *, state: str, max_age_days: int | None, limit: int
    ) -> list[tuple[Vulnerability, Assessment | None]]:
        query = (
            select(Vulnerability, Assessment)
            .join(
                Assessment,
                and_(
                    Assessment.vulnerability_id == Vulnerability.id,
                    Assessment.workspace_id == self.workspace_id,
                ),
            )
            .where(Vulnerability.duplicate_of.is_(None))
        )
        if state == "unqualified":
            query = query.where(Assessment.status.in_(UNQUALIFIED))
        elif state == "open":
            query = query.where(Assessment.status.in_((*UNQUALIFIED, "monitoring")))
        if max_age_days is not None:
            since = self.now - timedelta(days=max_age_days)
            query = query.where(Vulnerability.first_seen_at >= since)
        rows = await self.db.execute(
            query.order_by(Vulnerability.first_seen_at.desc()).limit(limit)
        )
        return [(v, a) for v, a in rows.tuples()]

    async def attach_evidence(
        self, vulnerability: Vulnerability, collected_item_id: uuid.UUID, kind: str
    ) -> bool:
        added = await self.db.execute(
            insert(Evidence)
            .values(
                id=uuid.uuid4(),
                vulnerability_id=vulnerability.id,
                collected_item_id=collected_item_id,
                kind=kind,
                note="",
                confidence=Decimal("0.5"),
                added_by_type="workflow",
                workspace_id=self.workspace_id,
            )
            .on_conflict_do_nothing(constraint="uq_evidence_item")
            .returning(Evidence.id)
        )
        return added.scalar_one_or_none() is not None

    # Collected content (untrusted) ------------------------------------------------

    async def store_collected(self, source_type: str, **fields: Any) -> tuple[uuid.UUID, bool]:
        stored, new = await store_item(
            self.db,
            self.workspace_id,
            source_type=source_type,
            now=self.now,
            run_id=self.run_id,
            node_id=self.node_id,
            **fields,
        )
        return stored.id, new

    async def remember(self, namespace: str, key_hash: str, days: int) -> bool:
        """True the first time a key is seen (until it expires)."""
        await self.db.execute(
            delete(DedupeKey).where(
                DedupeKey.workspace_id == self.workspace_id,
                DedupeKey.namespace == namespace[:100],
                DedupeKey.key_hash == key_hash,
                DedupeKey.expires_at < self.now,
            )
        )
        added = await self.db.execute(
            insert(DedupeKey)
            .values(
                workspace_id=self.workspace_id,
                namespace=namespace[:100],
                key_hash=key_hash,
                first_seen_at=self.now,
                expires_at=self.now + timedelta(days=days),
            )
            .on_conflict_do_nothing()
            .returning(DedupeKey.key_hash)
        )
        return added.scalar_one_or_none() is not None

    # People ---------------------------------------------------------------------

    async def analyst_emails(self) -> list[str]:
        rows = await self.db.execute(
            select(User.email)
            .join(WorkspaceMembership, WorkspaceMembership.user_id == User.id)
            .where(
                WorkspaceMembership.workspace_id == self.workspace_id,
                WorkspaceMembership.role == "analyst",
                User.status == "active",
            )
        )
        return sorted(rows.scalars())
