"""Bulletins in the client portal (spec 06 §2, plan 8.3 and 8.4, ADR-031).

Read only through ``portal_bulletins_v`` and ``portal_bulletin_history_v``: the views
already restrict the rows to the request's organisation, the TLP rules and what was
published (never a draft, never an update in progress). Responses are allow-listed
schemas; nothing internal (author, workspace, fields, vulnerabilities) exists in them.
"""

import asyncio
import json
import uuid
from datetime import date, datetime, time, timedelta
from html import escape
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import column, func, literal, literal_column, or_, select, table, text
from sqlalchemy.sql import ColumnElement
from sqlalchemy.sql.elements import TextClause

from app.iam.deps import DB, require
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.portal.branding import load_branding
from app.portal.pdf import PdfBulletin, render_pdf

Reader = Annotated[Principal, Depends(require(Permission.PORTAL_BULLETINS_READ))]
PAGE_SIZE = 20
PDF_TIMEOUT_S = 30
MAX_QUERY = 200

BULLETINS = table(
    "portal_bulletins_v",
    column("id"),
    column("ref"),
    column("language"),
    column("team"),
    column("title"),
    column("severity"),
    column("tlp"),
    column("rev_no"),
    column("cves"),
    column("technologies"),
    column("published_at"),
    column("updated_at"),
    column("html"),
    column("markdown"),
)
HISTORY = table(
    "portal_bulletin_history_v",
    column("bulletin_id"),
    column("rev_no"),
    column("kind"),
    column("at"),
)
SUMMARY = [
    BULLETINS.c.id,
    BULLETINS.c.ref,
    BULLETINS.c.language,
    BULLETINS.c.team,
    BULLETINS.c.title,
    BULLETINS.c.severity,
    BULLETINS.c.tlp,
    BULLETINS.c.cves,
    BULLETINS.c.technologies,
    BULLETINS.c.published_at,
    BULLETINS.c.updated_at,
]


class TechnologyOut(BaseModel):
    vendor: str
    product: str
    name: str


class PortalBulletinOut(BaseModel):
    id: uuid.UUID
    ref: str
    title: str
    severity: str | None
    tlp: str
    language: str
    team: str
    cves: list[str]
    technologies: list[TechnologyOut]
    published_at: datetime
    updated_at: datetime


class PortalBulletinPage(BaseModel):
    items: list[PortalBulletinOut]
    total: int
    page: int
    page_size: int


class HistoryOut(BaseModel):
    kind: str
    at: datetime


class PortalBulletinDetailOut(PortalBulletinOut):
    html: str
    history: list[HistoryOut]


def _technologies(raw: Any) -> list[TechnologyOut]:
    values = json.loads(raw) if isinstance(raw, str) else raw or []
    return [
        TechnologyOut(
            vendor=str(t.get("vendor", "")),
            product=str(t.get("product", "")),
            name=str(t.get("name", "")),
        )
        for t in values
        if isinstance(t, dict)
    ]


def _summary(row: Any) -> PortalBulletinOut:
    return PortalBulletinOut(
        id=row.id,
        ref=row.ref,
        title=row.title,
        severity=row.severity,
        tlp=row.tlp,
        language=row.language,
        team=row.team,
        cves=list(row.cves or []),
        technologies=_technologies(row.technologies),
        published_at=row.published_at,
        updated_at=row.updated_at,
    )


def _filters(
    q: str | None,
    severity: list[str],
    technology: str | None,
    since: date | None,
    until: date | None,
) -> list[ColumnElement[bool] | TextClause]:
    conditions: list[ColumnElement[bool] | TextClause] = []
    if q and q.strip():
        words = q.strip()
        config: ColumnElement[Any] = literal_column(
            "'simple'::regconfig"
        )  # a constant, never user input
        document = func.to_tsvector(config, BULLETINS.c.title + literal(" ") + BULLETINS.c.markdown)
        conditions.append(
            or_(
                document.op("@@")(func.plainto_tsquery(config, words)),
                BULLETINS.c.ref.ilike(f"%{_like(words)}%", escape="\\"),
                text(":cve = ANY (portal_bulletins_v.cves)").bindparams(cve=words.upper()),
            )
        )
    if severity:
        conditions.append(BULLETINS.c.severity.in_(severity))
    if technology and technology.strip():
        pattern = f"%{_like(technology.strip())}%"
        conditions.append(
            text(
                "EXISTS (SELECT 1 FROM jsonb_array_elements(portal_bulletins_v.technologies) t "
                "WHERE t ->> 'name' ILIKE :tech ESCAPE '\\' OR t ->> 'vendor' ILIKE :tech "
                "ESCAPE '\\' OR t ->> 'product' ILIKE :tech ESCAPE '\\')"
            ).bindparams(tech=pattern)
        )
    if since:
        conditions.append(BULLETINS.c.published_at >= datetime.combine(since, time.min))
    if until:
        conditions.append(
            BULLETINS.c.published_at < datetime.combine(until + timedelta(days=1), time.min)
        )
    return conditions


def pdf_bulletin(row: Any) -> PdfBulletin:
    return PdfBulletin(
        ref=row.ref,
        title=row.title,
        severity=row.severity,
        tlp=row.tlp,
        team=row.team,
        language=row.language,
        published_at=row.published_at,
        updated_at=row.updated_at,
        cves=list(row.cves or []),
        technologies=[t.name for t in _technologies(row.technologies)],
        html=row.html,
    )


def _like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_portal_bulletin_router() -> APIRouter:
    router = APIRouter(prefix="/bulletins", tags=["bulletins"])

    @router.get("", response_model=PortalBulletinPage)
    async def list_bulletins(
        principal: Reader,
        db: DB,
        q: Annotated[str | None, Query(max_length=MAX_QUERY)] = None,
        severity: Annotated[list[Literal["critical", "high", "medium", "low"]], Query()] = [],  # noqa: B006
        technology: Annotated[str | None, Query(max_length=100)] = None,
        since: date | None = None,
        until: date | None = None,
        page: Annotated[int, Query(ge=1, le=1000)] = 1,
    ) -> PortalBulletinPage:
        """Bulletins published for the organisation, most recently updated first."""
        del principal  # the view filters on the organisation of the session
        conditions = _filters(q, list(severity), technology, since, until)
        total = (
            await db.execute(select(func.count()).select_from(BULLETINS).where(*conditions))
        ).scalar_one()
        rows = await db.execute(
            select(*SUMMARY)
            .where(*conditions)
            .order_by(BULLETINS.c.updated_at.desc(), BULLETINS.c.ref.desc())
            .limit(PAGE_SIZE)
            .offset((page - 1) * PAGE_SIZE)
        )
        return PortalBulletinPage(
            items=[_summary(r) for r in rows], total=total, page=page, page_size=PAGE_SIZE
        )

    async def _detail(db: Any, bulletin_id: uuid.UUID) -> Any:
        row = (
            await db.execute(
                select(*SUMMARY, BULLETINS.c.html, BULLETINS.c.markdown).where(
                    BULLETINS.c.id == bulletin_id
                )
            )
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="not_found")
        return row

    @router.get("/{bulletin_id}", response_model=PortalBulletinDetailOut)
    async def get_bulletin(
        bulletin_id: uuid.UUID, principal: Reader, db: DB
    ) -> PortalBulletinDetailOut:
        del principal
        row = await _detail(db, bulletin_id)
        history = await db.execute(
            select(HISTORY.c.kind, HISTORY.c.at)
            .where(HISTORY.c.bulletin_id == bulletin_id)
            .order_by(HISTORY.c.at.desc())
        )
        return PortalBulletinDetailOut(
            **_summary(row).model_dump(),
            html=row.html,
            history=[HistoryOut(kind=h.kind, at=h.at) for h in history],
        )

    @router.get("/{bulletin_id}/export")
    async def export_bulletin(
        bulletin_id: uuid.UUID,
        principal: Reader,
        db: DB,
        format: Annotated[Literal["markdown", "html", "pdf"], Query()] = "markdown",
    ) -> Response:
        """The published bulletin as a file; the HTML is the server-sanitised rendering
        in a minimal document that loads nothing and runs nothing; the PDF is rendered
        in a thread, bounded in time, and fetches nothing either (``app.portal.pdf``)."""
        del principal
        row = await _detail(db, bulletin_id)
        if format == "pdf":
            branding = await load_branding(db)
            issuer = branding.issuer_name if branding else ""
            logo = branding.logo_png if branding else None
            try:
                data = await asyncio.wait_for(
                    asyncio.to_thread(render_pdf, pdf_bulletin(row), issuer, logo),
                    PDF_TIMEOUT_S,
                )
            except TimeoutError:
                raise HTTPException(status_code=503, detail="pdf_unavailable") from None
            return Response(
                data,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{row.ref}.pdf"',
                    "X-Content-Type-Options": "nosniff",
                },
            )
        if format == "markdown":
            content, media, extension = row.markdown, "text/markdown; charset=utf-8", "md"
        else:
            content = (
                '<!doctype html>\n<html lang="' + escape(row.language) + '"><head>'
                '<meta charset="utf-8">'
                '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
                "style-src 'unsafe-inline'\">"
                f"<title>{escape(row.ref)} — {escape(row.title)}</title></head>"
                f"<body><p>{escape(row.ref)} · TLP:{escape(row.tlp)} · {escape(row.team)}</p>"
                f"{row.html}</body></html>\n"
            )
            media, extension = "text/html; charset=utf-8", "html"
        return Response(
            content.encode(),
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{row.ref}.{extension}"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router
