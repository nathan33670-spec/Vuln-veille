"""Platform branding (Q46): the issuer's name and logo on the portal and in the PDFs.

The logo is decoded by Pillow, bounded in size and pixels, and re-encoded as PNG:
metadata and anything appended to the file are dropped, so what is stored and served
is an image Vuln-Veille produced, never the uploaded bytes. PNG and JPEG only (no SVG:
it is a document that can carry scripts).
"""

import base64
import binascii
import io
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, SmallInteger, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.audit.service import AuditEntry, record
from app.core.db import Base
from app.iam.deps import DB, SettingsDep, ensure_recent_step_up, require
from app.iam.permissions import Permission
from app.iam.principal import Principal

MAX_UPLOAD_BYTES = 512 * 1024
MAX_SOURCE_PIXELS = 4096 * 4096
LOGO_BOX = (600, 200)
MAX_LOGO_BYTES = 300 * 1024
ACCEPTED_FORMATS = frozenset({"PNG", "JPEG"})


class PlatformBranding(Base):
    __tablename__ = "platform_branding"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    issuer_name: Mapped[str] = mapped_column(Text, default="")
    logo_png: Mapped[bytes | None] = mapped_column(LargeBinary)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1)


class LogoError(ValueError):
    pass


def normalize_logo(raw: bytes) -> bytes:
    """A PNG re-encoded from an uploaded PNG or JPEG, fitted in ``LOGO_BOX``."""
    if len(raw) > MAX_UPLOAD_BYTES:
        raise LogoError("logo_too_large")
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            if probe.format not in ACCEPTED_FORMATS:
                raise LogoError("logo_format")
            if probe.width * probe.height > MAX_SOURCE_PIXELS:
                raise LogoError("logo_too_large")
            probe.verify()
        with Image.open(io.BytesIO(raw)) as image:
            image.load()
            converted = image.convert("RGBA")
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombError):
        raise LogoError("logo_format") from None
    converted.thumbnail(LOGO_BOX)
    out = io.BytesIO()
    converted.save(out, format="PNG", optimize=True)
    data = out.getvalue()
    if len(data) > MAX_LOGO_BYTES:
        raise LogoError("logo_too_large")
    return data


class BrandingOut(BaseModel):
    issuer_name: str
    has_logo: bool
    version: int


class BrandingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer_name: str = Field(max_length=120)
    version: int


class LogoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_base64: str = Field(max_length=MAX_UPLOAD_BYTES * 4 // 3 + 8)
    version: int


async def load_branding(db: DB) -> PlatformBranding | None:
    return await db.get(PlatformBranding, 1)


def _out(branding: PlatformBranding | None) -> BrandingOut:
    if branding is None:
        return BrandingOut(issuer_name="", has_logo=False, version=0)
    return BrandingOut(
        issuer_name=branding.issuer_name,
        has_logo=branding.logo_png is not None,
        version=branding.version,
    )


def _logo_response(branding: PlatformBranding | None) -> Response:
    if branding is None or branding.logo_png is None:
        raise HTTPException(status_code=404, detail="not_found")
    return Response(
        branding.logo_png,
        media_type="image/png",
        headers={"Cache-Control": "private, max-age=300", "X-Content-Type-Options": "nosniff"},
    )


Admin = Annotated[Principal, Depends(require(Permission.PLATFORM_BRANDING_MANAGE))]


def build_admin_branding_router() -> APIRouter:
    router = APIRouter(prefix="/admin/branding", tags=["branding"])

    async def _locked(db: DB, version: int) -> PlatformBranding:
        branding = await db.get(PlatformBranding, 1, with_for_update=True)
        if branding is None:
            raise HTTPException(status_code=404, detail="not_found")
        if branding.version != version:
            raise HTTPException(status_code=409, detail="version_conflict")
        return branding

    async def _save(
        db: DB, request: Request, principal: Principal, branding: PlatformBranding, what: str
    ) -> BrandingOut:
        branding.version += 1
        branding.updated_by = principal.user_id
        branding.updated_at = datetime.now(UTC)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action=f"branding.{what}",
                target_type="platform",
                target_id="branding",
                details={"issuer_name": branding.issuer_name},
            ),
        )
        await db.commit()
        return _out(branding)

    @router.get("", response_model=BrandingOut)
    async def get_branding(principal: Admin, db: DB) -> BrandingOut:
        del principal
        return _out(await load_branding(db))

    @router.get("/logo")
    async def get_logo(principal: Admin, db: DB) -> Response:
        del principal
        return _logo_response(await load_branding(db))

    @router.put("", response_model=BrandingOut)
    async def put_branding(
        body: BrandingIn, request: Request, principal: Admin, db: DB
    ) -> BrandingOut:
        branding = await _locked(db, body.version)
        branding.issuer_name = body.issuer_name.strip()
        return await _save(db, request, principal, branding, "updated")

    @router.put("/logo", response_model=BrandingOut)
    async def put_logo(
        body: LogoIn, request: Request, principal: Admin, settings: SettingsDep, db: DB
    ) -> BrandingOut:
        ensure_recent_step_up(principal, settings)
        try:
            raw = base64.b64decode(body.data_base64, validate=True)
            logo = normalize_logo(raw)
        except binascii.Error:
            raise HTTPException(status_code=422, detail="logo_format") from None
        except LogoError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        branding = await _locked(db, body.version)
        branding.logo_png = logo
        return await _save(db, request, principal, branding, "logo_updated")

    @router.delete("/logo", response_model=BrandingOut)
    async def delete_logo(
        request: Request, principal: Admin, settings: SettingsDep, db: DB, version: int
    ) -> BrandingOut:
        ensure_recent_step_up(principal, settings)
        branding = await _locked(db, version)
        branding.logo_png = None
        return await _save(db, request, principal, branding, "logo_removed")

    return router


PortalUser = Annotated[Principal, Depends(require(Permission.PORTAL_BULLETINS_READ))]


def build_portal_branding_router() -> APIRouter:
    router = APIRouter(prefix="/branding", tags=["branding"])

    @router.get("", response_model=BrandingOut)
    async def portal_branding(principal: PortalUser, db: DB) -> BrandingOut:
        del principal
        return _out(await load_branding(db))

    @router.get("/logo")
    async def portal_logo(principal: PortalUser, db: DB) -> Response:
        del principal
        return _logo_response(await load_branding(db))

    return router
