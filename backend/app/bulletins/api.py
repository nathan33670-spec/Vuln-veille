"""Bulletin templates and settings API (phase 6, spec 04 §1-2).

Templates are versioned like workflows: a change is a new immutable version, validated
(fields, sources, render template), activated explicitly. Previews and the template
selection run on the server, with the rendering rules of production.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.bulletins.facts import Facts, vulnerability_facts
from app.bulletins.models import BulletinSettings, BulletinTemplate, BulletinTemplateVersion
from app.bulletins.render import RenderError, markdown_to_html, render_markdown
from app.bulletins.schemas import (
    MatchOut,
    PreviewIn,
    PreviewOut,
    SettingsIn,
    SettingsOut,
    TemplateCreate,
    TemplateDetailOut,
    TemplateOut,
    TemplateUpdate,
    TemplateVersionCreate,
    TemplateVersionDetailOut,
    TemplateVersionOut,
)
from app.bulletins.selection import Candidate, block_reasons, preview_fields, select_template
from app.bulletins.spec import TemplateSpec, parse_spec
from app.core.errors import ApiError
from app.core.ids import uuid7
from app.iam.deps import DB, WorkspaceAccess, require_workspace
from app.iam.permissions import Permission

Reader = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.BULLETIN_DRAFT))]
Manager = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.TEMPLATE_MANAGE))]
SettingsAdmin = Annotated[
    WorkspaceAccess, Depends(require_workspace(Permission.WORKSPACE_SETTINGS_MANAGE))
]


def now() -> datetime:
    return datetime.now(UTC)


def validated_spec(raw: dict[str, Any]) -> TemplateSpec:
    """The template spec, or 422 with ``{path, code}`` errors (no submitted value)."""
    try:
        return parse_spec(raw)
    except ValidationError as exc:
        errors = [
            {"path": ".".join(str(p) for p in e["loc"]), "code": e["type"]}
            for e in exc.errors()[:100]
        ]
        raise ApiError(422, "invalid_template", errors) from None


async def _audit(
    db: AsyncSession,
    request: Request,
    access: WorkspaceAccess,
    action: str,
    target: str,
    **data: object,
) -> None:
    await record(
        db,
        access.principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="bulletin_template",
            target_id=target,
            workspace_id=access.workspace.id,
            details=data,
        ),
    )


async def _template(
    db: AsyncSession, access: WorkspaceAccess, template_id: uuid.UUID
) -> BulletinTemplate:
    template = await db.get(BulletinTemplate, template_id)
    if template is None or template.workspace_id != access.workspace.id:
        raise HTTPException(status_code=404, detail="not_found")
    return template


async def _versions(db: AsyncSession, template_id: uuid.UUID) -> list[BulletinTemplateVersion]:
    rows = await db.execute(
        select(BulletinTemplateVersion)
        .where(BulletinTemplateVersion.template_id == template_id)
        .order_by(BulletinTemplateVersion.version_no.desc())
    )
    return list(rows.scalars())


async def _settings(db: AsyncSession, workspace_id: uuid.UUID) -> BulletinSettings | None:
    return await db.get(BulletinSettings, workspace_id)


def _version_out(v: BulletinTemplateVersion) -> TemplateVersionOut:
    return TemplateVersionOut(
        id=v.id,
        version_no=v.version_no,
        language=v.language,
        priority=v.priority,
        comment=v.comment,
        created_by=v.created_by,
        created_at=v.created_at,
    )


def _template_out(
    template: BulletinTemplate,
    versions: list[BulletinTemplateVersion],
    default_id: uuid.UUID | None,
) -> TemplateOut:
    active = next((v for v in versions if v.id == template.active_version_id), None)
    shown = active or (versions[0] if versions else None)
    spec = shown.spec if shown else {}
    return TemplateOut(
        id=template.id,
        name=template.name,
        description=template.description,
        status=template.status,
        seed_key=template.seed_key,
        active_version_no=active.version_no if active else None,
        latest_version_no=versions[0].version_no if versions else None,
        language=shown.language if shown else None,
        priority=shown.priority if shown else None,
        tlp=spec.get("tlp"),
        rule_count=len(spec.get("match_rules") or []),
        is_default=template.id == default_id,
        updated_at=template.updated_at,
        version=template.version,
    )


async def _detail(db: AsyncSession, template: BulletinTemplate) -> TemplateDetailOut:
    versions = await _versions(db, template.id)
    settings = await _settings(db, template.workspace_id)
    out = _template_out(template, versions, settings.default_template_id if settings else None)
    active = next((v for v in versions if v.id == template.active_version_id), None)
    return TemplateDetailOut(
        **out.model_dump(),
        versions=[_version_out(v) for v in versions],
        active_spec=active.spec if active else None,
        latest_spec=versions[0].spec if versions else None,
    )


async def active_candidates(db: AsyncSession, workspace_id: uuid.UUID) -> list[Candidate]:
    """The active templates of a workspace, with their active version."""
    rows = await db.execute(
        select(BulletinTemplate, BulletinTemplateVersion)
        .join(
            BulletinTemplateVersion,
            BulletinTemplateVersion.id == BulletinTemplate.active_version_id,
        )
        .where(BulletinTemplate.workspace_id == workspace_id, BulletinTemplate.status == "active")
    )
    return [
        Candidate(template.id, version.id, template.name, parse_spec(version.spec))
        for template, version in rows.all()
    ]


async def _facts(db: AsyncSession, access: WorkspaceAccess, vulnerability_id: uuid.UUID) -> Facts:
    facts = await vulnerability_facts(db, access.workspace.id, vulnerability_id)
    if facts is None:
        raise HTTPException(status_code=404, detail="vulnerability_not_found")
    return facts


def _routes_templates(router: APIRouter) -> None:
    @router.get("/bulletin-templates", response_model=list[TemplateOut])
    async def list_templates(access: Reader, db: DB) -> list[TemplateOut]:
        templates = (
            await db.execute(
                select(BulletinTemplate)
                .where(BulletinTemplate.workspace_id == access.workspace.id)
                .order_by(BulletinTemplate.name)
            )
        ).scalars()
        settings = await _settings(db, access.workspace.id)
        default_id = settings.default_template_id if settings else None
        return [_template_out(t, await _versions(db, t.id), default_id) for t in templates]

    @router.post("/bulletin-templates", response_model=TemplateDetailOut, status_code=201)
    async def create_template(
        body: TemplateCreate, request: Request, access: Manager, db: DB
    ) -> TemplateDetailOut:
        spec = validated_spec(body.spec)
        moment = now()
        template = BulletinTemplate(
            id=uuid7(),
            workspace_id=access.workspace.id,
            name=body.name,
            description=body.description,
            status="draft",
            created_at=moment,
            updated_at=moment,
        )
        db.add(template)
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="name_taken") from None
        db.add(
            BulletinTemplateVersion(
                id=uuid7(),
                workspace_id=access.workspace.id,
                template_id=template.id,
                version_no=1,
                spec=spec.model_dump(mode="json", by_alias=True),
                language=spec.language,
                priority=spec.priority,
                comment=body.comment,
                created_by=access.principal.user_id,
                created_at=moment,
            )
        )
        await _audit(
            db, request, access, "bulletin_template.created", str(template.id), name=body.name
        )
        await db.commit()
        return await _detail(db, template)

    @router.get("/bulletin-templates/match", response_model=MatchOut)
    async def match_template(
        access: Reader,
        db: DB,
        vulnerability_id: uuid.UUID,
        language: Annotated[str | None, Query(pattern=r"^(fr|en)$")] = None,
    ) -> MatchOut:
        """The template the system would apply to this vulnerability, and why."""
        facts = await _facts(db, access, vulnerability_id)
        settings = await _settings(db, access.workspace.id)
        selection = select_template(
            await active_candidates(db, access.workspace.id),
            facts,
            default_template_id=settings.default_template_id if settings else None,
            language=language,
        )
        if selection is None:
            raise HTTPException(status_code=404, detail="no_template")
        version = await db.get(BulletinTemplateVersion, selection.candidate.version_id)
        assert version is not None  # noqa: S101 - joined above
        return MatchOut(
            template_id=selection.candidate.template_id,
            template_name=selection.candidate.name,
            version_no=version.version_no,
            language=selection.candidate.spec.language,
            rule_index=selection.rule_index,
            reasons=selection.reasons,
        )

    @router.post("/bulletin-templates/preview", response_model=PreviewOut)
    async def preview_template(body: PreviewIn, access: Reader, db: DB) -> PreviewOut:
        """A template rendered on the server, like a real bulletin: computed fields from a
        real vulnerability, AI and manual fields as placeholders (no AI call)."""
        spec = validated_spec(body.spec)
        facts = await _facts(db, access, body.vulnerability_id) if body.vulnerability_id else None
        fields = preview_fields(spec, facts)
        if body.fields:
            fields.update({k: v for k, v in body.fields.items() if spec.field(k) is not None})
        matched: bool | None = None
        reasons: list[str] = []
        if facts is not None and spec.match_rules:
            for block in spec.match_rules:
                found = block_reasons(block, facts)
                if found is not None:
                    matched, reasons = True, found
                    break
            else:
                matched = False
        try:
            markdown = render_markdown(
                spec.render_template,
                {"fields": fields, "tlp": body.tlp or spec.tlp, "language": spec.language},
            )
        except RenderError as exc:
            raise ApiError(
                422, "render_failed", [{"path": "render_template", "code": str(exc)}]
            ) from None
        return PreviewOut(
            fields=fields,
            markdown=markdown,
            html=markdown_to_html(markdown),
            matches=matched,
            reasons=reasons,
        )

    @router.get("/bulletin-templates/{template_id}", response_model=TemplateDetailOut)
    async def get_template(template_id: uuid.UUID, access: Reader, db: DB) -> TemplateDetailOut:
        return await _detail(db, await _template(db, access, template_id))

    @router.patch("/bulletin-templates/{template_id}", response_model=TemplateDetailOut)
    async def update_template(
        template_id: uuid.UUID, body: TemplateUpdate, request: Request, access: Manager, db: DB
    ) -> TemplateDetailOut:
        template = await _template(db, access, template_id)
        await db.refresh(template, with_for_update=True)
        if template.version != body.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        if body.status == "active" and template.active_version_id is None:
            raise HTTPException(status_code=422, detail="no_active_version")
        changes = body.model_dump(exclude_unset=True, exclude={"version"})
        for key, value in changes.items():
            setattr(template, key, value)
        template.version += 1
        template.updated_at = now()
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="name_taken") from None
        await _audit(
            db,
            request,
            access,
            "bulletin_template.updated",
            str(template.id),
            fields=sorted(changes),
        )
        await db.commit()
        return await _detail(db, template)

    @router.post(
        "/bulletin-templates/{template_id}/versions",
        response_model=TemplateVersionDetailOut,
        status_code=201,
    )
    async def create_version(
        template_id: uuid.UUID,
        body: TemplateVersionCreate,
        request: Request,
        access: Manager,
        db: DB,
    ) -> TemplateVersionDetailOut:
        template = await _template(db, access, template_id)
        await db.refresh(template, with_for_update=True)
        latest = (
            await db.execute(
                select(func.max(BulletinTemplateVersion.version_no)).where(
                    BulletinTemplateVersion.template_id == template.id
                )
            )
        ).scalar_one()
        if body.base_version_no is not None and body.base_version_no != (latest or 0):
            raise HTTPException(status_code=409, detail="version_conflict")
        spec = validated_spec(body.spec)
        version = BulletinTemplateVersion(
            id=uuid7(),
            workspace_id=access.workspace.id,
            template_id=template.id,
            version_no=(latest or 0) + 1,
            spec=spec.model_dump(mode="json", by_alias=True),
            language=spec.language,
            priority=spec.priority,
            comment=body.comment,
            created_by=access.principal.user_id,
            created_at=now(),
        )
        db.add(version)
        template.updated_at = now()
        await _audit(
            db, request, access, "bulletin_template.version_created", str(template.id),
            version_no=version.version_no,
        )  # fmt: skip
        await db.commit()
        return TemplateVersionDetailOut(**_version_out(version).model_dump(), spec=version.spec)

    @router.get(
        "/bulletin-templates/{template_id}/versions/{version_no}",
        response_model=TemplateVersionDetailOut,
    )
    async def get_version(
        template_id: uuid.UUID, version_no: int, access: Reader, db: DB
    ) -> TemplateVersionDetailOut:
        template = await _template(db, access, template_id)
        version = next(
            (v for v in await _versions(db, template.id) if v.version_no == version_no), None
        )
        if version is None:
            raise HTTPException(status_code=404, detail="not_found")
        return TemplateVersionDetailOut(**_version_out(version).model_dump(), spec=version.spec)

    @router.post(
        "/bulletin-templates/{template_id}/versions/{version_no}/activate",
        response_model=TemplateDetailOut,
    )
    async def activate_version(
        template_id: uuid.UUID, version_no: int, request: Request, access: Manager, db: DB
    ) -> TemplateDetailOut:
        template = await _template(db, access, template_id)
        await db.refresh(template, with_for_update=True)
        version = next(
            (v for v in await _versions(db, template.id) if v.version_no == version_no), None
        )
        if version is None:
            raise HTTPException(status_code=404, detail="not_found")
        validated_spec(version.spec)  # still valid with today's rules
        template.active_version_id = version.id
        template.status = "active"
        template.version += 1
        template.updated_at = now()
        await _audit(
            db,
            request,
            access,
            "bulletin_template.activated",
            str(template.id),
            version_no=version_no,
        )
        await db.commit()
        return await _detail(db, template)


def _settings_out(settings: BulletinSettings) -> SettingsOut:
    return SettingsOut(
        ref_prefix=settings.ref_prefix,
        review_required=settings.review_required,
        default_template_id=settings.default_template_id,
        updated_at=settings.updated_at,
        version=settings.version,
    )


def _routes_settings(router: APIRouter) -> None:
    @router.get("/bulletin-settings", response_model=SettingsOut)
    async def get_settings(access: Reader, db: DB) -> SettingsOut:
        settings = await _settings(db, access.workspace.id)
        if settings is None:
            raise HTTPException(status_code=404, detail="not_found")
        return _settings_out(settings)

    @router.put("/bulletin-settings", response_model=SettingsOut)
    async def put_settings(
        body: SettingsIn, request: Request, access: SettingsAdmin, db: DB
    ) -> SettingsOut:
        settings = await db.get(BulletinSettings, access.workspace.id, with_for_update=True)
        if settings is None:
            settings = BulletinSettings(workspace_id=access.workspace.id, version=0)
            db.add(settings)
        elif settings.version != body.version:
            raise HTTPException(status_code=409, detail="version_conflict")
        if body.default_template_id is not None:
            await _template(db, access, body.default_template_id)
        settings.ref_prefix = body.ref_prefix
        settings.review_required = body.review_required
        settings.default_template_id = body.default_template_id
        settings.updated_by = access.principal.user_id
        settings.updated_at = now()
        settings.version = (settings.version or 0) + 1
        await record(
            db,
            access.principal.audit_ctx(request),
            AuditEntry(
                action="bulletin_settings.updated",
                target_type="workspace",
                target_id=str(access.workspace.id),
                workspace_id=access.workspace.id,
                details={
                    "ref_prefix": body.ref_prefix,
                    "review_required": body.review_required,
                },
            ),
        )
        await db.commit()
        await db.refresh(settings)
        return _settings_out(settings)


def build_bulletin_router() -> APIRouter:
    router = APIRouter(tags=["bulletins"])
    workspace = APIRouter(prefix="/workspaces/{workspace}")
    _routes_templates(workspace)
    _routes_settings(workspace)
    router.include_router(workspace)
    return router
