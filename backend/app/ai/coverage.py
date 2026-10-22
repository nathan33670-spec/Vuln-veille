"""X coverage indicator (plan 4.18, spec 07 §2.1).

Share of the CVEs investigated by the workspace's social media agent for which a
relevant X discussion was found by the free reading: a post cited in the agent's
validated output and actually read through the official oEmbed during the same run
(a made-up or withdrawn URL does not count). It is compared with a sample the
analysts check by hand: recall (posts they found that the agent found too) and
precision (posts the agent found on CVEs they judged without discussion).

The search engine choice behind it is settled (Q30, Q32): layers 1 and 2 only.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Text, delete, func, select
from sqlalchemy.dialects.postgresql import ARRAY, insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.ai.agents.models import AgentRun, AgentStep, AIAgent
from app.audit.service import AuditEntry, record
from app.connectors.types.x_reader import POST_URL, canonical
from app.core.db import Base, UUIDPrimaryKeyMixin
from app.core.ids import uuid7
from app.iam.deps import DB, WorkspaceAccess, require_workspace
from app.iam.permissions import Permission

SOCIAL_PRESET = "social"
MAX_RUNS = 2000
CvePath = Annotated[str, Path(pattern=r"^CVE-\d{4}-\d{4,19}$")]
Reader = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.WORKFLOW_READ))]
Checker = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.VULN_QUALIFY))]


class XCoverageCheck(UUIDPrimaryKeyMixin, Base):
    """Schema: migration 0013_x_coverage."""

    __tablename__ = "x_coverage_checks"

    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    cve_id: Mapped[str] = mapped_column(Text)
    has_discussion: Mapped[bool] = mapped_column(Boolean)
    urls: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    checked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def posts_in(value: Any) -> set[str]:
    """Canonical X post URLs anywhere in a JSON value."""
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return {canonical(handle, post_id) for handle, post_id in POST_URL.findall(text)}


def read_posts(steps: list[AgentStep]) -> set[str]:
    """Posts actually read (oEmbed answered with a text) during a run."""
    read: set[str] = set()
    for step in steps:
        payload = step.payload
        if step.type != "tool_result" or payload.get("name") != "x_read" or payload.get("error"):
            continue
        documents = (payload.get("content") or {}).get("documents") or []
        for document in documents:
            if isinstance(document, dict) and "untrusted_document" in document:
                read |= posts_in(document["untrusted_document"].get("url") or "")
    return read


async def found_by_agent(
    db: AsyncSession, workspace_id: uuid.UUID, since: datetime
) -> dict[str, bool]:
    """CVE -> whether the social agent found a relevant X discussion (latest runs win)."""
    runs = list(
        (
            await db.execute(
                select(AgentRun)
                .join(AIAgent, AIAgent.id == AgentRun.agent_id)
                .where(
                    AgentRun.workspace_id == workspace_id,
                    AIAgent.preset == SOCIAL_PRESET,
                    AgentRun.status == "succeeded",
                    AgentRun.queued_at >= since,
                )
                .order_by(AgentRun.queued_at)
                .limit(MAX_RUNS)
            )
        ).scalars()
    )
    steps: dict[uuid.UUID, list[AgentStep]] = {r.id: [] for r in runs}
    if runs:
        rows = await db.execute(
            select(AgentStep).where(
                AgentStep.agent_run_id.in_(list(steps)), AgentStep.type == "tool_result"
            )
        )
        for step in rows.scalars():
            steps[step.agent_run_id].append(step)
    found: dict[str, bool] = {}
    for run in runs:
        cve_id = run.input.get("cve_id")
        if not isinstance(cve_id, str):
            continue
        cited = posts_in(run.output or {})
        found[cve_id.upper()] = found.get(cve_id.upper(), False) or bool(
            cited & read_posts(steps[run.id])
        )
    return found


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def indicator(found: dict[str, bool], checks: list[XCoverageCheck]) -> dict[str, Any]:
    with_x = sum(found.values())
    compared = [c for c in checks if c.cve_id in found]
    positives = [c for c in compared if c.has_discussion]
    negatives = [c for c in compared if not c.has_discussion]
    true_positives = sum(1 for c in positives if found[c.cve_id])
    false_positives = sum(1 for c in negatives if found[c.cve_id])
    return {
        "investigated": len(found),
        "with_x_discussion": with_x,
        "coverage_rate": _ratio(with_x, len(found)),
        "sample": {
            "checked": len(checks),
            "compared": len(compared),
            "with_discussion": len(positives),
            "found_by_agent": true_positives,
            "missed": [c.cve_id for c in positives if not found[c.cve_id]][:50],
            "recall": _ratio(true_positives, len(positives)),
            "precision": _ratio(true_positives, true_positives + false_positives),
        },
    }


# API ---------------------------------------------------------------------------


class CheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    has_discussion: bool
    urls: list[str] = Field(default_factory=list, max_length=20)
    notes: str = Field(default="", max_length=1000)


class CheckOut(BaseModel):
    cve_id: str
    has_discussion: bool
    urls: list[str]
    notes: str
    checked_by: uuid.UUID | None
    checked_at: datetime


class CoverageOut(BaseModel):
    days: int
    investigated: int
    with_x_discussion: int
    coverage_rate: float | None
    sample: dict[str, Any]


def _check_out(check: XCoverageCheck) -> CheckOut:
    return CheckOut(
        cve_id=check.cve_id,
        has_discussion=check.has_discussion,
        urls=check.urls,
        notes=check.notes,
        checked_by=check.checked_by,
        checked_at=check.checked_at,
    )


async def _checks(db: AsyncSession, workspace_id: uuid.UUID) -> list[XCoverageCheck]:
    rows = await db.execute(
        select(XCoverageCheck)
        .where(XCoverageCheck.workspace_id == workspace_id)
        .order_by(XCoverageCheck.cve_id)
    )
    return list(rows.scalars())


def build_coverage_router() -> APIRouter:
    router = APIRouter(prefix="/workspaces/{workspace}", tags=["x-coverage"])

    @router.get("/x-coverage", response_model=CoverageOut)
    async def get_coverage(
        access: Reader, db: DB, days: int = Query(default=30, ge=1, le=365)
    ) -> CoverageOut:
        since = datetime.now(UTC) - timedelta(days=days)
        found = await found_by_agent(db, access.workspace.id, since)
        return CoverageOut(days=days, **indicator(found, await _checks(db, access.workspace.id)))

    @router.get("/x-coverage/checks", response_model=list[CheckOut])
    async def list_checks(access: Reader, db: DB) -> list[CheckOut]:
        return [_check_out(c) for c in await _checks(db, access.workspace.id)]

    @router.put("/x-coverage/checks/{cve_id}", response_model=CheckOut)
    async def put_check(
        cve_id: CvePath, body: CheckIn, request: Request, access: Checker, db: DB
    ) -> CheckOut:
        """An analyst's hand check: did a relevant X discussion exist for this CVE?"""
        urls = sorted(posts_in("\n".join(body.urls)))
        if len(urls) != len(set(body.urls)):
            raise HTTPException(status_code=422, detail="not_x_post_urls")
        values = {
            "has_discussion": body.has_discussion,
            "urls": urls,
            "notes": body.notes,
            "checked_by": access.principal.user_id,
            "checked_at": datetime.now(UTC),
        }
        statement = insert(XCoverageCheck).values(
            id=uuid7(), workspace_id=access.workspace.id, cve_id=cve_id.upper(), **values
        )
        await db.execute(
            statement.on_conflict_do_update(constraint="uq_x_coverage_checks", set_=values)
        )
        await record(
            db,
            access.principal.audit_ctx(request),
            AuditEntry(
                action="x_coverage.checked",
                target_type="x_coverage_check",
                target_id=cve_id.upper(),
                workspace_id=access.workspace.id,
                details={"has_discussion": body.has_discussion},
            ),
        )
        await db.commit()
        check = (
            await db.execute(
                select(XCoverageCheck).where(
                    XCoverageCheck.workspace_id == access.workspace.id,
                    XCoverageCheck.cve_id == cve_id.upper(),
                )
            )
        ).scalar_one()
        return _check_out(check)

    @router.delete("/x-coverage/checks/{cve_id}", status_code=204)
    async def delete_check(cve_id: CvePath, access: Checker, db: DB) -> None:
        await db.execute(
            delete(XCoverageCheck).where(
                XCoverageCheck.workspace_id == access.workspace.id,
                XCoverageCheck.cve_id == cve_id.upper(),
            )
        )
        await db.commit()

    return router
