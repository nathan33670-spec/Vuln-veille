"""Technology catalogue API (spec 01 §3, RBAC: technology.manage, technology.merge_delete).

Reading needs ``vuln.read`` (every internal user). Merging keeps the merged entry,
pointing to its target: watch scopes of every team follow the pointer at match time,
so no team's configuration has to be rewritten across workspaces.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import ColumnElement, String, func, literal, literal_column, or_, select, text
from sqlalchemy.exc import IntegrityError

from app.audit.service import AuditEntry, record
from app.iam.deps import DB, require
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.technologies.models import Technology
from app.technologies.schemas import (
    CpeSuggestionOut,
    TechnologyCreate,
    TechnologyMerge,
    TechnologyOut,
    TechnologyUpdate,
)

Reader = Annotated[Principal, Depends(require(Permission.VULN_READ))]
Curator = Annotated[Principal, Depends(require(Permission.TECHNOLOGY_MANAGE))]
Admin = Annotated[Principal, Depends(require(Permission.TECHNOLOGY_MERGE_DELETE))]
WORD_SIMILARITY = 0.45
Search = Annotated[str | None, Query(max_length=100)]

SEARCH_TEXT: ColumnElement[str] = literal_column(
    "(display_name || ' ' || vendor || ' ' || product)", String
)


def technology_out(t: Technology) -> TechnologyOut:
    return TechnologyOut(
        id=t.id,
        vendor=t.vendor,
        product=t.product,
        display_name=t.display_name,
        aliases=t.aliases,
        cpe_prefixes=t.cpe_prefixes,
        purls=t.purls,
        category=t.category,
        status=t.status,
        merged_into=t.merged_into,
        version=t.version,
        updated_at=t.updated_at,
    )


async def _get(db: DB, technology_id: uuid.UUID) -> Technology:
    technology = await db.get(Technology, technology_id)
    if technology is None:
        raise HTTPException(status_code=404, detail="not_found")
    return technology


async def _audit(
    db: DB, request: Request, principal: Principal, action: str, t: Technology, **details: object
) -> None:
    await record(
        db,
        principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="technology",
            target_id=str(t.id),
            details={"vendor": t.vendor, "product": t.product, **details},
        ),
    )


def build_technology_router() -> APIRouter:
    router = APIRouter(prefix="/technologies", tags=["technologies"])

    @router.get("", response_model=list[TechnologyOut])
    async def search_technologies(
        principal: Reader,
        db: DB,
        q: Search = None,
        include_merged: bool = False,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> list[TechnologyOut]:
        query = select(Technology)
        if not include_merged:
            query = query.where(Technology.status != "merged")
        if q:
            term = q.strip().lower()
            # word_similarity: the query against the best-matching words, so typos and
            # partial names match ("exchnge" finds "Exchange Server").
            query = query.where(
                or_(
                    func.word_similarity(term, SEARCH_TEXT) > WORD_SIMILARITY,
                    SEARCH_TEXT.ilike(f"%{term.replace('%', '').replace('_', '')}%"),
                    literal(q.strip()) == func.any(Technology.aliases),
                )
            ).order_by(func.word_similarity(term, SEARCH_TEXT).desc(), Technology.display_name)
        else:
            query = query.order_by(Technology.display_name)
        rows = await db.execute(query.limit(limit))
        return [technology_out(t) for t in rows.scalars()]

    @router.get("/cpe-suggestions", response_model=list[CpeSuggestionOut])
    async def cpe_suggestions(
        principal: Curator,
        db: DB,
        q: Annotated[str, Query(min_length=2, max_length=100)],
    ) -> list[CpeSuggestionOut]:
        """Vendor/product pairs seen in the catalogue's CPE configurations (from NVD)."""
        rows = await db.execute(
            text(
                "SELECT split_part(c, ':', 4) AS vendor, split_part(c, ':', 5) AS product, "
                "split_part(c, ':', 3) AS part, count(DISTINCT r.cve_id) AS n "
                "FROM cve_records r, unnest(r.cpe_criteria) c "
                "WHERE split_part(c, ':', 4) || ' ' || split_part(c, ':', 5) ILIKE :pattern "
                "GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 50"
            ),
            {"pattern": "%" + q.strip().lower().replace("%", "").replace("_", "\\_") + "%"},
        )
        found = rows.all()
        existing = (
            {(t.vendor, t.product): t.id for t in (await db.execute(select(Technology))).scalars()}
            if found
            else {}
        )
        return [
            CpeSuggestionOut(
                vendor=v,
                product=p,
                cpe_prefix=f"cpe:2.3:{part}:{v}:{p}",
                cve_count=n,
                existing_technology_id=existing.get((v, p)),
            )
            for v, p, part, n in found
        ]

    @router.get("/{technology_id}", response_model=TechnologyOut)
    async def get_technology(technology_id: uuid.UUID, principal: Reader, db: DB) -> TechnologyOut:
        return technology_out(await _get(db, technology_id))

    @router.post("", response_model=TechnologyOut, status_code=201)
    async def create_technology(
        body: TechnologyCreate, request: Request, principal: Curator, db: DB
    ) -> TechnologyOut:
        technology = Technology(
            **body.model_dump(), created_by=principal.user_id, version=1, status="active"
        )
        db.add(technology)
        try:
            await db.flush()
        except IntegrityError as exc:
            await db.rollback()
            raise HTTPException(status_code=409, detail="technology_exists") from exc
        await _audit(db, request, principal, "technology.created", technology)
        await db.commit()
        await db.refresh(technology)
        return technology_out(technology)

    @router.patch("/{technology_id}", response_model=TechnologyOut)
    async def update_technology(
        technology_id: uuid.UUID,
        body: TechnologyUpdate,
        request: Request,
        principal: Curator,
        db: DB,
    ) -> TechnologyOut:
        technology = await _get(db, technology_id)
        if body.version != technology.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        if technology.status == "merged":
            raise HTTPException(status_code=409, detail="technology_merged")
        changes = body.model_dump(exclude={"version"}, exclude_none=True)
        for field, value in changes.items():
            setattr(technology, field, value)
        if changes:
            technology.version += 1
            await _audit(
                db, request, principal, "technology.updated", technology, fields=sorted(changes)
            )
            await db.commit()
            await db.refresh(technology)
        return technology_out(technology)

    @router.post("/{technology_id}/merge", response_model=TechnologyOut)
    async def merge_technology(
        technology_id: uuid.UUID,
        body: TechnologyMerge,
        request: Request,
        principal: Admin,
        db: DB,
    ) -> TechnologyOut:
        source, target = await _get(db, technology_id), await _get(db, body.into)
        if source.id == target.id or target.status == "merged" or source.status == "merged":
            raise HTTPException(status_code=409, detail="invalid_merge")
        target.aliases = sorted({*target.aliases, *source.aliases, source.display_name})
        target.cpe_prefixes = sorted({*target.cpe_prefixes, *source.cpe_prefixes})
        target.purls = sorted({*target.purls, *source.purls})
        target.version += 1
        source.status, source.merged_into = "merged", target.id
        source.version += 1
        await _audit(db, request, principal, "technology.merged", source, into=str(target.id))
        await db.commit()
        await db.refresh(target)
        return technology_out(target)

    @router.delete("/{technology_id}", status_code=204)
    async def delete_technology(
        technology_id: uuid.UUID, request: Request, principal: Admin, db: DB
    ) -> None:
        technology = await _get(db, technology_id)
        await _audit(db, request, principal, "technology.deleted", technology)
        await db.delete(technology)
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            raise HTTPException(status_code=409, detail="technology_in_use") from exc

    return router
