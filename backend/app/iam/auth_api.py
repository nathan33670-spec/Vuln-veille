"""Authentication and account endpoints, mounted on both applications (``/auth``, ``/account``).

Error details are stable codes (``invalid_credentials``, ``mfa_required``...) translated
by the front end. Failures never reveal whether an account exists.
"""

import uuid
from datetime import timedelta
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditContext, AuditEntry, record
from app.core.access import public_endpoint
from app.core.config import Audience, Settings
from app.core.crypto import AesGcmBox, keyed_hash
from app.core.mailer import Mailer
from app.core.rate_limit import RateLimiter
from app.core.rls import set_context
from app.iam import totp as totp_lib
from app.iam.deps import (
    DB,
    SettingsDep,
    audience_of,
    authenticated,
    ensure_recent_step_up,
    pending_or_authenticated,
)
from app.iam.models import (
    AuthToken,
    ClientMembership,
    ClientOrganization,
    RecoveryCode,
    Session,
    User,
    UserTotp,
)
from app.iam.passwords import (
    PasswordPolicyError,
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.iam.principal import Principal
from app.iam.schemas import (
    ClientOrgOut,
    CsrfOut,
    EnrollmentOut,
    ForgotPasswordIn,
    LoginIn,
    LoginOut,
    MeOut,
    MfaCodeIn,
    PasswordChangeIn,
    RecoveryCodesOut,
    SessionOut,
    StepUpIn,
    TokenPasswordIn,
    WorkspaceOut,
)
from app.iam.sessions import (
    clear_session_cookie,
    create_session,
    csrf_token_for,
    promote_session,
    set_session_cookie,
    utcnow,
)
from app.iam.tokens import hash_token, issue_token, send_password_reset

MAX_MFA_ATTEMPTS = 5
LOCKOUT_THRESHOLD = 5
MAX_LOCKOUT_MINUTES = 60

USER_TYPE_FOR: dict[Audience, str] = {"backoffice": "internal", "portal": "client"}

Authenticated = Annotated[Principal, Depends(authenticated())]
PendingOrAuthenticated = Annotated[Principal, Depends(pending_or_authenticated())]
Public = Depends(public_endpoint)


def _limiter(request: Request) -> RateLimiter:
    return cast(RateLimiter, request.app.state.rate_limiter)


def _mailer(request: Request) -> Mailer:
    return cast(Mailer, request.app.state.mailer)


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _anonymous_ctx(request: Request) -> AuditContext:
    return AuditContext(ip=_ip(request), request_id=getattr(request.state, "request_id", None))


def _totp_box(settings: Settings) -> AesGcmBox:
    return AesGcmBox(settings.kek_totp_bytes)


def _policy_error(exc: PasswordPolicyError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


async def _rate_limit(request: Request, bucket: str, key: str, limit: int, window: int) -> None:
    if not await _limiter(request).hit(bucket, key, limit, window):
        raise HTTPException(status_code=429, detail="rate_limited")


async def _confirmed_totp(db: AsyncSession, user_id: uuid.UUID) -> UserTotp | None:
    totp = await db.get(UserTotp, user_id)
    return totp if totp is not None and totp.confirmed_at is not None else None


async def _client_mfa_required(db: AsyncSession, user: User) -> bool | None:
    """None if the client account cannot log in (no active organization)."""
    row = (
        await db.execute(
            select(ClientOrganization)
            .join(ClientMembership, ClientMembership.client_org_id == ClientOrganization.id)
            .where(ClientMembership.user_id == user.id)
        )
    ).scalar_one_or_none()
    if row is None or row.status != "active":
        return None
    return bool(row.settings.get("mfa_required", False))


async def _store_recovery_codes(
    db: AsyncSession, settings: Settings, user_id: uuid.UUID
) -> list[str]:
    await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    codes = totp_lib.new_recovery_codes()
    for code in codes:
        db.add(
            RecoveryCode(
                user_id=user_id, code_hash=keyed_hash(settings.secret_key_bytes, code, "recovery")
            )
        )
    await db.flush()
    return codes


async def _check_second_factor(
    db: AsyncSession, settings: Settings, user_id: uuid.UUID, code: str, *, allow_recovery: bool
) -> Literal["totp", "recovery"] | None:
    totp = await _confirmed_totp(db, user_id)
    if totp is None:
        return None
    secret = _totp_box(settings).decrypt(totp.secret_enc, user_id.bytes).decode()
    step = totp_lib.verify_totp(secret, code, totp.last_used_step)
    if step is not None:
        totp.last_used_step = step
        return "totp"
    if not allow_recovery:
        return None
    normalized = totp_lib.normalize_recovery_code(code)
    if not normalized:
        return None
    recovery = (
        await db.execute(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user_id,
                RecoveryCode.code_hash
                == keyed_hash(settings.secret_key_bytes, normalized, "recovery"),
                RecoveryCode.used_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if recovery is None:
        return None
    recovery.used_at = utcnow()
    return "recovery"


def build_auth_router() -> APIRouter:
    router = APIRouter(tags=["auth"])

    @router.post("/auth/login", response_model=LoginOut, dependencies=[Public])
    async def login(
        body: LoginIn, request: Request, response: Response, db: DB, settings: SettingsDep
    ) -> LoginOut:
        audience = audience_of(request)
        email = body.email.lower()
        ip = _ip(request) or "unknown"
        await _rate_limit(request, "login_ip", ip, 20, 60)
        await _rate_limit(request, "login_email", email, 10, 300)

        await set_context(db, login_email=email)
        user = (
            await db.execute(
                select(User).where(User.email == email, User.user_type == USER_TYPE_FOR[audience])
            )
        ).scalar_one_or_none()
        now = utcnow()
        if user is not None:
            await set_context(db, user_id=user.id)
        locked = user is not None and user.locked_until is not None and user.locked_until > now
        password_ok = verify_password(
            user.password_hash if user else None, body.password, settings.password_hash_profile
        )
        client_mfa_required: bool | None = False
        if user is not None and user.user_type == "client" and password_ok:
            client_mfa_required = await _client_mfa_required(db, user)

        if (
            user is None
            or not password_ok
            or locked
            or user.status != "active"
            or client_mfa_required is None
        ):
            reason = "unknown_account" if user is None else "rejected"
            if user is not None and not password_ok and not locked:
                user.failed_login_count += 1
                if user.failed_login_count >= LOCKOUT_THRESHOLD:
                    minutes = min(
                        2 ** (user.failed_login_count - LOCKOUT_THRESHOLD), MAX_LOCKOUT_MINUTES
                    )
                    user.locked_until = now + timedelta(minutes=minutes)
                    reason = "locked"
            await record(
                db,
                _anonymous_ctx(request),
                AuditEntry(
                    action="auth.login",
                    outcome="failure",
                    target_type="user" if user else None,
                    target_id=str(user.id) if user else None,
                    details={"reason": reason, "audience": audience},
                ),
            )
            await db.commit()
            raise HTTPException(status_code=401, detail="invalid_credentials")

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        if user.password_hash and needs_rehash(user.password_hash, settings.password_hash_profile):
            user.password_hash = hash_password(body.password, settings.password_hash_profile)

        mfa_enabled = await _confirmed_totp(db, user.id) is not None
        enrollment_required = not mfa_enabled and (
            user.user_type == "internal" or bool(client_mfa_required)
        )
        pending = mfa_enabled or enrollment_required
        token, _ = await create_session(
            db,
            settings,
            user,
            audience,
            pending=pending,
            enrollment_required=enrollment_required,
            ip=_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        await record(
            db,
            AuditContext(
                actor_user_id=user.id,
                actor_type="user",
                ip=_ip(request),
                request_id=getattr(request.state, "request_id", None),
            ),
            AuditEntry(
                action="auth.login",
                target_type="user",
                target_id=str(user.id),
                details={"audience": audience, "second_factor_pending": pending},
            ),
        )
        await db.commit()
        set_session_cookie(response, audience, token)
        status: Literal["authenticated", "mfa_required", "mfa_enrollment_required"] = (
            "mfa_enrollment_required"
            if enrollment_required
            else "mfa_required"
            if mfa_enabled
            else "authenticated"
        )
        return LoginOut(status=status, csrf_token=csrf_token_for(settings, token))

    @router.post("/auth/mfa/verify", response_model=CsrfOut)
    async def mfa_verify(
        body: MfaCodeIn,
        request: Request,
        response: Response,
        principal: PendingOrAuthenticated,
        db: DB,
        settings: SettingsDep,
    ) -> CsrfOut:
        session = principal.session
        if not principal.pending or session.mfa_enrollment_required:
            raise HTTPException(status_code=409, detail="no_pending_verification")
        method = await _check_second_factor(
            db, settings, principal.user_id, body.code, allow_recovery=True
        )
        if method is None:
            session.mfa_attempts += 1
            if session.mfa_attempts >= MAX_MFA_ATTEMPTS:
                session.revoked_at = utcnow()
            await record(
                db,
                principal.audit_ctx(request),
                AuditEntry(
                    action="auth.mfa_verify",
                    outcome="failure",
                    details={"attempts": session.mfa_attempts},
                ),
            )
            await db.commit()
            raise HTTPException(status_code=401, detail="invalid_code")
        token = await promote_session(db, settings, session)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(action="auth.mfa_verify", details={"method": method}),
        )
        await db.commit()
        set_session_cookie(response, audience_of(request), token)
        return CsrfOut(csrf_token=csrf_token_for(settings, token))

    @router.post("/auth/mfa/enroll", response_model=EnrollmentOut)
    async def mfa_enroll_start(
        principal: PendingOrAuthenticated, db: DB, settings: SettingsDep
    ) -> EnrollmentOut:
        if principal.mfa_enabled:
            raise HTTPException(status_code=409, detail="mfa_already_enabled")
        if principal.pending and not principal.session.mfa_enrollment_required:
            raise HTTPException(status_code=409, detail="mfa_required")
        enrollment = totp_lib.new_enrollment(principal.user.email)
        secret_enc = _totp_box(settings).encrypt(
            enrollment.secret.encode(), principal.user_id.bytes
        )
        existing = await db.get(UserTotp, principal.user_id)
        if existing is None:
            db.add(UserTotp(user_id=principal.user_id, secret_enc=secret_enc))
        else:
            existing.secret_enc = secret_enc
            existing.confirmed_at = None
            existing.last_used_step = None
        await db.commit()
        return EnrollmentOut(
            secret=enrollment.secret,
            otpauth_uri=enrollment.otpauth_uri,
            qr_data_uri=enrollment.qr_data_uri,
        )

    @router.post("/auth/mfa/enroll/confirm", response_model=RecoveryCodesOut)
    async def mfa_enroll_confirm(
        body: MfaCodeIn,
        request: Request,
        response: Response,
        principal: PendingOrAuthenticated,
        db: DB,
        settings: SettingsDep,
    ) -> RecoveryCodesOut:
        totp = await db.get(UserTotp, principal.user_id)
        if totp is None or totp.confirmed_at is not None:
            raise HTTPException(status_code=409, detail="no_enrollment_in_progress")
        secret = _totp_box(settings).decrypt(totp.secret_enc, principal.user_id.bytes).decode()
        step = totp_lib.verify_totp(secret, body.code, None)
        if step is None:
            principal.session.mfa_attempts += 1
            if principal.session.mfa_attempts >= MAX_MFA_ATTEMPTS:
                principal.session.revoked_at = utcnow()
            await db.commit()
            raise HTTPException(status_code=401, detail="invalid_code")
        totp.confirmed_at = utcnow()
        totp.last_used_step = step
        codes = await _store_recovery_codes(db, settings, principal.user_id)
        token = principal.session_token
        if principal.pending:
            token = await promote_session(db, settings, principal.session)
        else:
            principal.session.step_up_at = utcnow()
        await record(db, principal.audit_ctx(request), AuditEntry(action="auth.mfa_enrolled"))
        await db.commit()
        set_session_cookie(response, audience_of(request), token)
        return RecoveryCodesOut(recovery_codes=codes, csrf_token=csrf_token_for(settings, token))

    @router.post("/auth/logout", status_code=204)
    async def logout(
        request: Request, response: Response, principal: PendingOrAuthenticated, db: DB
    ) -> None:
        principal.session.revoked_at = utcnow()
        await record(db, principal.audit_ctx(request), AuditEntry(action="auth.logout"))
        await db.commit()
        clear_session_cookie(response, audience_of(request))

    @router.get("/auth/me", response_model=MeOut)
    async def me(principal: PendingOrAuthenticated, settings: SettingsDep) -> MeOut:
        grants = principal.grants
        client_org = (
            ClientOrgOut(
                id=grants.client_org_id,
                name=grants.client_org_name or "",
                role=grants.client_role or "",
            )
            if grants.client_org_id
            else None
        )
        return MeOut(
            id=principal.user.id,
            email=principal.user.email,
            display_name=principal.user.display_name,
            user_type=principal.user.user_type,
            locale=principal.user.locale,
            mfa_enabled=principal.mfa_enabled,
            pending_mfa=principal.pending,
            permissions=[] if principal.pending else sorted(grants.global_permissions),
            workspaces=[]
            if principal.pending
            else [
                WorkspaceOut(
                    slug=w.slug, name=w.name, role=w.role, permissions=sorted(w.permissions)
                )
                for w in sorted(grants.workspaces.values(), key=lambda w: w.slug)
            ],
            client_org=None if principal.pending else client_org,
            csrf_token=csrf_token_for(settings, principal.session_token),
        )

    @router.post("/auth/invitation/accept", status_code=204, dependencies=[Public])
    async def accept_invitation(
        body: TokenPasswordIn, request: Request, db: DB, settings: SettingsDep
    ) -> None:
        await _consume_token(request, db, settings, body, purpose="invitation")

    @router.post("/auth/password/forgot", status_code=202, dependencies=[Public])
    async def forgot_password(
        body: ForgotPasswordIn, request: Request, db: DB, settings: SettingsDep
    ) -> None:
        audience = audience_of(request)
        email = body.email.lower()
        ip = _ip(request) or "unknown"
        # Same answer whatever happens, so the endpoint cannot enumerate accounts.
        if not await _limiter(request).hit("forgot_ip", ip, 10, 3600):
            return
        if not await _limiter(request).hit("forgot_email", email, 3, 3600):
            return
        await set_context(db, login_email=email)
        user = (
            await db.execute(
                select(User).where(User.email == email, User.user_type == USER_TYPE_FOR[audience])
            )
        ).scalar_one_or_none()
        if user is None or user.status != "active":
            return
        await set_context(db, user_id=user.id)
        token = await issue_token(db, settings, user, "password_reset", audience, None)
        await record(
            db,
            _anonymous_ctx(request),
            AuditEntry(
                action="auth.password_reset_requested", target_type="user", target_id=str(user.id)
            ),
        )
        await db.commit()
        send_password_reset(_mailer(request), settings, user, audience, token)

    @router.post("/auth/password/reset", status_code=204, dependencies=[Public])
    async def reset_password(
        body: TokenPasswordIn, request: Request, db: DB, settings: SettingsDep
    ) -> None:
        await _consume_token(request, db, settings, body, purpose="password_reset")

    @router.post("/auth/step-up", response_model=CsrfOut)
    async def step_up(
        body: StepUpIn,
        request: Request,
        principal: Authenticated,
        db: DB,
        settings: SettingsDep,
    ) -> CsrfOut:
        await _rate_limit(request, "step_up", str(principal.session.public_id), 5, 300)
        if principal.mfa_enabled:
            ok = (
                body.code is not None
                and await _check_second_factor(
                    db, settings, principal.user_id, body.code, allow_recovery=False
                )
                is not None
            )
        else:
            ok = body.password is not None and verify_password(
                principal.user.password_hash, body.password, settings.password_hash_profile
            )
        if not ok:
            await record(
                db,
                principal.audit_ctx(request),
                AuditEntry(action="auth.step_up", outcome="failure"),
            )
            await db.commit()
            raise HTTPException(status_code=401, detail="invalid_code")
        principal.session.step_up_at = utcnow()
        await record(db, principal.audit_ctx(request), AuditEntry(action="auth.step_up"))
        await db.commit()
        return CsrfOut(csrf_token=csrf_token_for(settings, principal.session_token))

    @router.post("/account/password", status_code=204)
    async def change_password(
        body: PasswordChangeIn,
        request: Request,
        principal: Authenticated,
        db: DB,
        settings: SettingsDep,
    ) -> None:
        await _rate_limit(request, "password_change", str(principal.user_id), 5, 900)
        user = principal.user
        if not verify_password(
            user.password_hash, body.current_password, settings.password_hash_profile
        ):
            await record(
                db,
                principal.audit_ctx(request),
                AuditEntry(action="account.password_changed", outcome="failure"),
            )
            await db.commit()
            raise HTTPException(status_code=400, detail="invalid_current_password")
        try:
            check_password_policy(body.new_password, user.email)
        except PasswordPolicyError as exc:
            raise _policy_error(exc) from exc
        user.password_hash = hash_password(body.new_password, settings.password_hash_profile)
        user.password_changed_at = utcnow()
        # Every other session is revoked; the current one stays.
        await db.execute(
            update(Session)
            .where(Session.user_id == user.id, Session.id_hash != principal.session.id_hash)
            .where(Session.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        await record(
            db, principal.audit_ctx(request), AuditEntry(action="account.password_changed")
        )
        await db.commit()

    @router.get("/account/sessions", response_model=list[SessionOut])
    async def list_sessions(principal: Authenticated, db: DB) -> list[SessionOut]:
        now = utcnow()
        rows = (
            await db.execute(
                select(Session)
                .where(Session.user_id == principal.user_id, Session.revoked_at.is_(None))
                .where(Session.idle_expires_at > now, Session.absolute_expires_at > now)
                .order_by(Session.created_at.desc())
            )
        ).scalars()
        return [
            SessionOut(
                id=s.public_id,
                created_at=s.created_at,
                last_seen_at=s.last_seen_at,
                ip=str(s.ip) if s.ip else None,
                user_agent=s.user_agent,
                current=s.id_hash == principal.session.id_hash,
            )
            for s in rows
        ]

    @router.delete("/account/sessions/{session_id}", status_code=204)
    async def revoke_session(
        session_id: uuid.UUID, request: Request, principal: Authenticated, db: DB
    ) -> None:
        target = (
            await db.execute(
                select(Session).where(
                    Session.public_id == session_id, Session.user_id == principal.user_id
                )
            )
        ).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="not_found")
        target.revoked_at = utcnow()
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(
                action="account.session_revoked", target_type="session", target_id=str(session_id)
            ),
        )
        await db.commit()

    @router.post("/account/mfa/recovery-codes", response_model=RecoveryCodesOut)
    async def regenerate_recovery_codes(
        request: Request, principal: Authenticated, db: DB, settings: SettingsDep
    ) -> RecoveryCodesOut:
        if not principal.mfa_enabled:
            raise HTTPException(status_code=409, detail="mfa_not_enabled")
        ensure_recent_step_up(principal, settings)
        codes = await _store_recovery_codes(db, settings, principal.user_id)
        await record(
            db,
            principal.audit_ctx(request),
            AuditEntry(action="account.recovery_codes_regenerated"),
        )
        await db.commit()
        return RecoveryCodesOut(
            recovery_codes=codes, csrf_token=csrf_token_for(settings, principal.session_token)
        )

    @router.delete("/account/mfa", status_code=204)
    async def disable_mfa(
        request: Request, principal: Authenticated, db: DB, settings: SettingsDep
    ) -> None:
        """Clients only (MFA is optional for them, decision Q16), unless their org requires it."""
        if principal.user.user_type != "client":
            raise HTTPException(status_code=403, detail="mfa_mandatory")
        if await _client_mfa_required(db, principal.user):
            raise HTTPException(status_code=403, detail="mfa_mandatory")
        ensure_recent_step_up(principal, settings)
        await db.execute(delete(UserTotp).where(UserTotp.user_id == principal.user_id))
        await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == principal.user_id))
        await record(db, principal.audit_ctx(request), AuditEntry(action="account.mfa_disabled"))
        await db.commit()

    return router


async def _consume_token(
    request: Request,
    db: AsyncSession,
    settings: Settings,
    body: TokenPasswordIn,
    *,
    purpose: Literal["invitation", "password_reset"],
) -> None:
    audience = audience_of(request)
    await _rate_limit(request, "token_ip", _ip(request) or "unknown", 10, 300)
    token_hash = hash_token(settings, body.token)
    await set_context(db, token_hash=token_hash)
    token = (
        await db.execute(
            select(AuthToken).where(
                AuthToken.token_hash == token_hash,
                AuthToken.purpose == purpose,
                AuthToken.audience == audience,
            )
        )
    ).scalar_one_or_none()
    now = utcnow()
    if token is None or token.used_at is not None or token.expires_at <= now:
        raise HTTPException(status_code=400, detail="invalid_or_expired_token")
    await set_context(db, user_id=token.user_id)
    user = await db.get(User, token.user_id)
    expected_status = "invited" if purpose == "invitation" else "active"
    if user is None or user.status != expected_status:
        raise HTTPException(status_code=400, detail="invalid_or_expired_token")
    try:
        check_password_policy(body.password, user.email)
    except PasswordPolicyError as exc:
        raise _policy_error(exc) from exc

    user.password_hash = hash_password(body.password, settings.password_hash_profile)
    user.password_changed_at = now
    user.failed_login_count = 0
    user.locked_until = None
    user.status = "active"
    token.used_at = now
    await db.execute(
        update(Session)
        .where(Session.user_id == user.id, Session.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    action = "auth.invitation_accepted" if purpose == "invitation" else "auth.password_reset"
    await record(
        db,
        AuditContext(
            actor_user_id=user.id,
            actor_type="user",
            ip=_ip(request),
            request_id=getattr(request.state, "request_id", None),
        ),
        AuditEntry(action=action, target_type="user", target_id=str(user.id)),
    )
    await db.commit()
