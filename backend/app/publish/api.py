"""Publication connectors, API side (spec 05, ADR-030): targets, dry-run, mapping
preview, exports, and the private network requests with the administrators' queue.

The API never decrypts a secret (it holds no private keyring): a dry-run shows every
credential masked, and a request is sent only by the ``publish`` worker (7B).
"""

import ipaddress
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import ValidationError
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditEntry, record
from app.audit.service import record as record_audit
from app.bulletins.models import Bulletin
from app.connectors.base import Family
from app.connectors.models import Connector
from app.connectors.service import health_of
from app.core.errors import ApiError
from app.core.ids import uuid7
from app.core.tasks import TaskQueue
from app.iam.deps import (
    DB,
    SettingsDep,
    WorkspaceAccess,
    ensure_recent_step_up,
    require,
    require_workspace,
)
from app.iam.models import Workspace
from app.iam.permissions import Permission
from app.iam.principal import Principal
from app.publish.config import HttpGenericConfig
from app.publish.context import (
    Publication,
    PublishError,
    load_publication,
    publication_context,
    sample_context,
)
from app.publish.csaf import csaf_document
from app.publish.mapping import MappingError, build_payload, context_paths, validate_mapping
from app.publish.models import PrivateNetworkRequest, PushAttempt, PushRecord
from app.publish.request import build_request
from app.publish.runner import push_task
from app.publish.schemas import (
    AttemptOut,
    DecisionIn,
    DryRunIn,
    MappingPreviewIn,
    MappingPreviewOut,
    PreparedOut,
    PrivateNetworkIn,
    PrivateNetworkRequestOut,
    PushDetailOut,
    PushIn,
    PushOut,
    RevokeIn,
    TargetOut,
)
from app.publish.service import first_push, push_target, queue_push

Pusher = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.CONNECTOR_PUBLISH_PUSH))]
Manager = Annotated[
    WorkspaceAccess, Depends(require_workspace(Permission.CONNECTOR_PUBLISH_MANAGE))
]
Drafter = Annotated[WorkspaceAccess, Depends(require_workspace(Permission.BULLETIN_DRAFT))]
Approver = Annotated[Principal, Depends(require(Permission.CONNECTOR_ALLOW_PRIVATE_NETWORK))]
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 32
EXPORT_TYPES = {
    "csaf": ("application/json", "csaf.json"),
    "json": ("application/json", "json"),
    "markdown": ("text/markdown; charset=utf-8", "md"),
}


def now() -> datetime:
    return datetime.now(UTC)


def _refused(exc: PublishError) -> ApiError:
    code, _, where = exc.code.partition(":")
    return ApiError(422, code, [{"path": where, "code": code}] if where else None)


async def _target(db: AsyncSession, access: WorkspaceAccess, connector_id: uuid.UUID) -> Connector:
    """A publication connector of the workspace, or a global one (Q40)."""
    connector = await db.get(Connector, connector_id)
    if (
        connector is None
        or connector.family != Family.PUBLISH
        or connector.workspace_id not in (access.workspace.id, None)
    ):
        raise HTTPException(status_code=404, detail="not_found")
    return connector


def _config(raw: dict[str, Any]) -> HttpGenericConfig:
    try:
        return HttpGenericConfig.model_validate(raw)
    except ValidationError as exc:
        errors = [{"loc": list(e["loc"]), "type": e["type"]} for e in exc.errors()]
        raise ApiError(422, "invalid_config", errors) from None


def _prepared(config: HttpGenericConfig, publication: Publication, connector_id: str,
              remote_id: str | None) -> PreparedOut:  # fmt: skip
    try:
        prepared = build_request(
            config, publication, connector_id=connector_id, remote_id=remote_id
        )
    except PublishError as exc:
        raise _refused(exc) from None
    return PreparedOut(**prepared.redacted())


async def _audit(
    db: AsyncSession,
    request: Request,
    principal: Principal,
    action: str,
    connector_id: uuid.UUID,
    workspace_id: uuid.UUID | None,
    **details: Any,
) -> None:
    await record(
        db,
        principal.audit_ctx(request),
        AuditEntry(
            action=action,
            target_type="connector",
            target_id=str(connector_id),
            workspace_id=workspace_id,
            details=details,
        ),
    )


def _routes_publication(router: APIRouter) -> None:
    @router.get("/workspaces/{workspace}/publish-targets", response_model=list[TargetOut])
    async def list_targets(access: Pusher, db: DB) -> list[TargetOut]:
        rows = await db.execute(
            select(Connector)
            .where(
                Connector.family == Family.PUBLISH,
                or_(
                    Connector.workspace_id == access.workspace.id,
                    Connector.workspace_id.is_(None),
                ),
            )
            .order_by(Connector.name)
        )
        return [
            TargetOut(
                id=c.id,
                name=c.name,
                kind=c.kind,
                scope="global" if c.workspace_id is None else "workspace",
                enabled=c.enabled,
                health=health_of(c),
                body_format=(c.config.get("body") or {}).get("format"),
            )
            for c in rows.scalars()
        ]

    @router.post(
        "/workspaces/{workspace}/publish-targets/{connector_id}/dry-run",
        response_model=PreparedOut,
    )
    async def dry_run(
        connector_id: uuid.UUID, body: DryRunIn, access: Pusher, db: DB
    ) -> PreparedOut:
        """The exact request for a bulletin, credentials masked; nothing is sent."""
        connector = await _target(db, access, connector_id)
        try:
            publication = await load_publication(db, access.workspace.id, body.bulletin_id)
        except PublishError as exc:
            raise _refused(exc) from None
        config = _config(connector.config)
        return _prepared(config, publication, str(connector.id), body.remote_id)

    @router.post(
        "/workspaces/{workspace}/publish-mapping/preview", response_model=MappingPreviewOut
    )
    async def preview_mapping(body: MappingPreviewIn, access: Manager, db: DB) -> MappingPreviewOut:
        """The payload (and request) of a configuration being edited, on a real
        validated bulletin or on a fictitious example."""
        mapping = (body.config.get("body") or {}).get("mapping")
        errors: list[dict[str, Any]] = []
        if mapping is not None:
            errors += [{"loc": ["body", "mapping"], **e} for e in validate_mapping(mapping)]
        try:
            config: HttpGenericConfig | None = HttpGenericConfig.model_validate(body.config)
        except ValidationError as exc:
            config = None
            errors += [{"loc": list(e["loc"]), "type": e["type"]} for e in exc.errors()]
        publication: Publication | None = None
        if body.bulletin_id is not None:
            try:
                publication = await load_publication(db, access.workspace.id, body.bulletin_id)
            except PublishError as exc:
                raise _refused(exc) from None
        context = publication_context(publication) if publication else sample_context()
        payload: Any = None
        request_out: PreparedOut | None = None
        if mapping is not None and not validate_mapping(mapping):
            try:
                payload = build_payload(mapping, context)
            except MappingError as exc:
                errors.append({"loc": ["body", "mapping"], "path": exc.path, "code": exc.code})
        if config is not None and publication is not None:
            try:
                request_out = PreparedOut(
                    **build_request(config, publication, connector_id="preview").redacted()
                )
            except PublishError as exc:
                errors.append({"loc": ["request"], "code": exc.code})
        return MappingPreviewOut(
            valid=not errors,
            errors=errors,
            payload=payload,
            request=request_out,
            paths=context_paths(context),
            sample=publication is None,
        )

    @router.get("/workspaces/{workspace}/bulletins/{bulletin_id}/export")
    async def export_bulletin(
        bulletin_id: uuid.UUID,
        access: Drafter,
        db: DB,
        format: Annotated[Literal["csaf", "json", "markdown"], Query()] = "json",
    ) -> Response:
        """A validated bulletin as a file: CSAF 2.0, JSON (its publication data) or
        Markdown. Drafts are never exported."""
        try:
            publication = await load_publication(db, access.workspace.id, bulletin_id)
            if format == "markdown":
                content = publication.revision.rendered_markdown.encode()
            else:
                value = (
                    csaf_document(publication)
                    if format == "csaf"
                    else publication_context(publication)
                )
                if format == "json":
                    value.pop("remote_id", None)
                content = json.dumps(value, ensure_ascii=False, indent=2).encode()
        except PublishError as exc:
            raise _refused(exc) from None
        media, extension = EXPORT_TYPES[format]
        filename = f"{publication.bulletin.ref}.{extension}"
        return Response(
            content,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )


def _push_out(record: PushRecord, connector_name: str, ref: str | None) -> PushOut:
    return PushOut(
        id=record.id,
        bulletin_id=record.bulletin_id,
        bulletin_ref=ref,
        connector_id=record.connector_id,
        connector_name=connector_name,
        connector_version=record.connector_version,
        rev_no=record.rev_no,
        is_test=record.is_test,
        origin=record.origin,
        requested_by=record.requested_by,
        status=record.status,
        mode=record.mode,
        attempts=record.attempts,
        next_attempt_at=record.next_attempt_at,
        remote_id=record.remote_id,
        response_status=record.response_status,
        error=record.error,
        created_at=record.created_at,
        finished_at=record.finished_at,
    )


async def _out(db: AsyncSession, record: PushRecord) -> PushOut:
    connector = await db.get(Connector, record.connector_id)
    bulletin = await db.get(Bulletin, record.bulletin_id) if record.bulletin_id else None
    return _push_out(
        record, connector.name if connector else "", bulletin.ref if bulletin else None
    )


def _send(request: Request, record: PushRecord) -> None:
    name, kwargs, _ = push_task(record)
    cast(TaskQueue, request.app.state.tasks).send(name, kwargs)


def _routes_push(router: APIRouter) -> None:
    @router.post(
        "/workspaces/{workspace}/bulletins/{bulletin_id}/push",
        response_model=PushOut,
        status_code=202,
    )
    async def push_bulletin(
        bulletin_id: uuid.UUID,
        body: PushIn,
        request: Request,
        access: Pusher,
        settings: SettingsDep,
        db: DB,
    ) -> PushOut:
        """Queues a push of the validated bulletin; the first push of a bulletin to a
        connector needs a recent second factor (Q43)."""
        try:
            connector = await push_target(db, access.workspace.id, body.connector_id)
            publication = await load_publication(db, access.workspace.id, bulletin_id)
            if await first_push(db, bulletin_id, connector.id):
                ensure_recent_step_up(access.principal, settings)
            record = await queue_push(
                db, access.workspace.id, connector, publication,
                origin="user", requested_by=access.principal.user_id, now=now(),
            )  # fmt: skip
        except PublishError as exc:
            if exc.code == "connector_not_found":
                raise HTTPException(status_code=404, detail="not_found") from None
            if exc.code == "push_in_progress":
                raise HTTPException(status_code=409, detail=exc.code) from None
            raise _refused(exc) from None
        await record_audit(
            db,
            access.principal.audit_ctx(request),
            AuditEntry(
                action="bulletin.pushed",
                target_type="bulletin",
                target_id=str(bulletin_id),
                workspace_id=access.workspace.id,
                details={"connector_id": str(connector.id), "rev_no": record.rev_no},
            ),
        )
        await db.commit()
        _send(request, record)
        return _push_out(record, connector.name, publication.bulletin.ref)

    @router.post(
        "/workspaces/{workspace}/publish-targets/{connector_id}/test",
        response_model=PushOut,
        status_code=202,
    )
    async def test_target(
        connector_id: uuid.UUID, request: Request, access: Manager, db: DB
    ) -> PushOut:
        """Sends the fictitious example bulletin, marked « TEST », to the target."""
        try:
            connector = await push_target(db, access.workspace.id, connector_id)
        except PublishError as exc:
            if exc.code == "connector_not_found":
                raise HTTPException(status_code=404, detail="not_found") from None
            raise _refused(exc) from None
        record = await queue_push(
            db, access.workspace.id, connector, None,
            origin="test", requested_by=access.principal.user_id, now=now(),
        )  # fmt: skip
        await _audit(
            db, request, access.principal, "connector.test_pushed",
            connector.id, access.workspace.id,
        )  # fmt: skip
        await db.commit()
        _send(request, record)
        return _push_out(record, connector.name, None)

    @router.get("/workspaces/{workspace}/publications", response_model=list[PushOut])
    async def list_pushes(
        access: Pusher,
        db: DB,
        bulletin_id: uuid.UUID | None = None,
        connector_id: uuid.UUID | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> list[PushOut]:
        query = (
            select(PushRecord)
            .where(PushRecord.workspace_id == access.workspace.id)
            .order_by(PushRecord.created_at.desc())
            .limit(limit)
        )
        if bulletin_id:
            query = query.where(PushRecord.bulletin_id == bulletin_id)
        if connector_id:
            query = query.where(PushRecord.connector_id == connector_id)
        return [await _out(db, r) for r in (await db.execute(query)).scalars()]

    @router.get(
        "/workspaces/{workspace}/publications/{publication_id}", response_model=PushDetailOut
    )
    async def get_push(publication_id: uuid.UUID, access: Pusher, db: DB) -> PushDetailOut:
        record = await db.get(PushRecord, publication_id)
        if record is None or record.workspace_id != access.workspace.id:
            raise HTTPException(status_code=404, detail="not_found")
        attempts = await db.execute(
            select(PushAttempt)
            .where(PushAttempt.publication_id == record.id)
            .order_by(PushAttempt.attempt_no)
        )
        return PushDetailOut(
            **(await _out(db, record)).model_dump(),
            attempt_log=[
                AttemptOut(
                    attempt_no=a.attempt_no,
                    request=a.request,
                    response_status=a.response_status,
                    response_excerpt=a.response_excerpt,
                    error=a.error,
                    duration_ms=a.duration_ms,
                    started_at=a.started_at,
                )
                for a in attempts.scalars()
            ],
        )


def _networks(cidrs: list[str]) -> list[str]:
    """Private ranges only, none wider than /8 (IPv4) or /32 (IPv6)."""
    out = []
    for raw in cidrs:
        try:
            network = ipaddress.ip_network(raw.strip(), strict=True)
        except ValueError:
            raise ApiError(422, "invalid_cidr", [{"path": raw[:50], "code": "invalid"}]) from None
        minimum = MIN_PREFIX_V4 if network.version == 4 else MIN_PREFIX_V6  # noqa: PLR2004
        if not network.is_private or network.prefixlen < minimum:
            raise ApiError(422, "invalid_cidr", [{"path": str(network), "code": "not_private"}])
        out.append(str(network))
    return sorted(set(out))


async def _request_out(db: AsyncSession, row: PrivateNetworkRequest) -> PrivateNetworkRequestOut:
    workspace = await db.get(Workspace, row.workspace_id) if row.workspace_id else None
    return PrivateNetworkRequestOut(
        id=row.id,
        connector_id=row.connector_id,
        workspace_slug=workspace.slug if workspace else None,
        connector_name=row.connector_name,
        hosts=list(row.hosts),
        cidrs=[str(c) for c in row.cidrs],
        reason=row.reason,
        status=row.status,
        requested_by=row.requested_by,
        requested_at=row.requested_at,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
        decision_note=row.decision_note,
    )


async def _supersede(db: AsyncSession, connector_id: uuid.UUID) -> None:
    await db.execute(
        update(PrivateNetworkRequest)
        .where(
            PrivateNetworkRequest.connector_id == connector_id,
            PrivateNetworkRequest.status == "pending",
        )
        .values(status="superseded")
    )


def _routes_private_network(router: APIRouter) -> None:
    base = "/workspaces/{workspace}/connectors/publish/{connector_id}/private-network"

    @router.get(base, response_model=list[PrivateNetworkRequestOut])
    async def list_requests(
        connector_id: uuid.UUID, access: Manager, db: DB
    ) -> list[PrivateNetworkRequestOut]:
        connector = await _target(db, access, connector_id)
        rows = await db.execute(
            select(PrivateNetworkRequest)
            .where(PrivateNetworkRequest.connector_id == connector.id)
            .order_by(PrivateNetworkRequest.requested_at.desc())
            .limit(50)
        )
        return [await _request_out(db, r) for r in rows.scalars()]

    @router.post(base, response_model=PrivateNetworkRequestOut, status_code=201)
    async def request_private_network(
        connector_id: uuid.UUID,
        body: PrivateNetworkIn,
        request: Request,
        access: Manager,
        settings: SettingsDep,
        db: DB,
    ) -> PrivateNetworkRequestOut:
        """Asks the platform administrators to let this connector reach private
        ranges; nothing changes until one of them approves (Q41)."""
        ensure_recent_step_up(access.principal, settings)
        connector = await _target(db, access, connector_id)
        if connector.workspace_id != access.workspace.id:
            raise HTTPException(status_code=404, detail="not_found")
        cidrs = _networks(body.cidrs)
        await _supersede(db, connector.id)
        connector.allow_private_network = True
        connector.private_network_cidrs = cidrs
        row = PrivateNetworkRequest(
            id=uuid7(),
            connector_id=connector.id,
            workspace_id=connector.workspace_id,
            connector_name=connector.name,
            hosts=list(connector.egress_domains),
            cidrs=cidrs,
            reason=body.reason,
            status="pending",
            requested_by=access.principal.user_id,
            requested_at=now(),
        )
        db.add(row)
        await _audit(
            db, request, access.principal, "connector.private_network_requested",
            connector.id, connector.workspace_id, cidrs=cidrs, hosts=row.hosts,
        )  # fmt: skip
        await db.commit()
        return await _request_out(db, row)

    @router.delete(base, status_code=204)
    async def drop_private_network(
        connector_id: uuid.UUID,
        request: Request,
        access: Manager,
        settings: SettingsDep,
        db: DB,
    ) -> None:
        ensure_recent_step_up(access.principal, settings)
        connector = await _target(db, access, connector_id)
        if connector.workspace_id != access.workspace.id:
            raise HTTPException(status_code=404, detail="not_found")
        await _supersede(db, connector.id)
        connector.allow_private_network = False
        connector.private_network_cidrs = []
        await _audit(
            db, request, access.principal, "connector.private_network_dropped",
            connector.id, connector.workspace_id,
        )  # fmt: skip
        await db.commit()


def _routes_admin(router: APIRouter) -> None:
    @router.get("/admin/private-network-requests", response_model=list[PrivateNetworkRequestOut])
    async def admin_requests(
        principal: Approver,
        db: DB,
        status: Annotated[str | None, Query(pattern=r"^[a-z]{1,20}$")] = "pending",
    ) -> list[PrivateNetworkRequestOut]:
        """Every workspace's requests: name, hosts, ranges and reason only."""
        query = select(PrivateNetworkRequest).order_by(PrivateNetworkRequest.requested_at.desc())
        if status:
            query = query.where(PrivateNetworkRequest.status == status)
        rows = await db.execute(query.limit(200))
        return [await _request_out(db, r) for r in rows.scalars()]

    async def _decide(
        db: AsyncSession, request_id: uuid.UUID, expected: str
    ) -> PrivateNetworkRequest:
        row = await db.get(PrivateNetworkRequest, request_id)
        if row is None:
            raise HTTPException(status_code=404, detail="not_found")
        if row.status != expected:
            raise HTTPException(status_code=409, detail=f"not_{expected}")
        return row

    @router.post(
        "/admin/private-network-requests/{request_id}/decision",
        response_model=PrivateNetworkRequestOut,
    )
    async def decide(
        request_id: uuid.UUID,
        body: DecisionIn,
        request: Request,
        principal: Approver,
        settings: SettingsDep,
        db: DB,
    ) -> PrivateNetworkRequestOut:
        ensure_recent_step_up(principal, settings)
        row = await _decide(db, request_id, "pending")
        row.status = "approved" if body.approve else "rejected"
        row.decided_by, row.decided_at, row.decision_note = principal.user_id, now(), body.note
        await _audit(
            db, request, principal,
            "connector.private_network_approved" if body.approve
            else "connector.private_network_rejected",
            row.connector_id, row.workspace_id, cidrs=[str(c) for c in row.cidrs],
            hosts=list(row.hosts), request_id=str(row.id),
        )  # fmt: skip
        await db.commit()
        return await _request_out(db, row)

    @router.post(
        "/admin/private-network-requests/{request_id}/revoke",
        response_model=PrivateNetworkRequestOut,
    )
    async def revoke(
        request_id: uuid.UUID,
        body: RevokeIn,
        request: Request,
        principal: Approver,
        settings: SettingsDep,
        db: DB,
    ) -> PrivateNetworkRequestOut:
        ensure_recent_step_up(principal, settings)
        row = await _decide(db, request_id, "approved")
        row.status = "revoked"
        row.decided_by, row.decided_at, row.decision_note = principal.user_id, now(), body.note
        await _audit(
            db, request, principal, "connector.private_network_revoked",
            row.connector_id, row.workspace_id, request_id=str(row.id),
        )  # fmt: skip
        await db.commit()
        return await _request_out(db, row)


def build_publish_router() -> APIRouter:
    router = APIRouter(tags=["publication"])
    _routes_publication(router)
    _routes_push(router)
    _routes_private_network(router)
    _routes_admin(router)
    return router
