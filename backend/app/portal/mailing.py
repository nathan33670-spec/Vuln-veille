"""Bulletins by e-mail to the client users who asked for them (spec 06 §2, Q44, Q45).

At each publication and each published update, every active user of an organisation
allowed to see the bulletin, who opted in, receives the bulletin: the sanitised HTML,
a text version and the PDF (Q45: whatever the TLP shown on the portal, only to the
organisations allowed). A withdrawal sends a short notice to the same people. One
message per recipient (never a shared list of addresses); a snapshot is notified once.
"""

import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.bulletins.models import BulletinRevision, PublicationEvent
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.mailer import Attachment, Mail, deliver_smtp
from app.core.rls import init_context, set_context
from app.iam.models import ClientMembership, ClientOrganization, User
from app.portal.branding import PlatformBranding
from app.portal.pdf import PdfBulletin, render_pdf
from app.portal.preferences import NotificationPreference

log = get_logger(__name__)
SHARED_TLP = frozenset({"CLEAR", "GREEN"})
TARGETED_TLP = frozenset({"AMBER", "AMBER+STRICT"})
HANDLING = {
    "CLEAR": "TLP:CLEAR — diffusion libre.",
    "GREEN": "TLP:GREEN — diffusion limitée à votre communauté, hors canaux publics.",
    "AMBER": "TLP:AMBER — diffusion limitée à votre organisation et à ses clients, "
    "selon le besoin d'en connaître.",
    "AMBER+STRICT": "TLP:AMBER+STRICT — diffusion limitée à votre organisation.",
}


def visible_to(event: PublicationEvent, org_id: uuid.UUID) -> bool:
    """The rule of ``portal_bulletins_v`` (Q22), for addressing e-mails."""
    if event.tlp in SHARED_TLP:
        return event.audience_type == "all_clients" or org_id in event.audience_org_ids
    if event.tlp in TARGETED_TLP:
        return event.audience_type == "selected" and org_id in event.audience_org_ids
    return False  # RED, and anything unknown


@dataclass(frozen=True)
class MailDeps:
    settings: Settings
    send: Callable[[Mail], None]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


async def _recipients(db: AsyncSession, event: PublicationEvent) -> list[str]:
    orgs = [
        o.id
        for o in (
            await db.execute(
                select(ClientOrganization).where(ClientOrganization.status == "active")
            )
        ).scalars()
        if visible_to(event, o.id)
    ]
    if not orgs:
        return []
    rows = await db.execute(
        select(User.email)
        .join(ClientMembership, ClientMembership.user_id == User.id)
        .join(NotificationPreference, NotificationPreference.user_id == User.id)
        .where(
            ClientMembership.client_org_id.in_(orgs),
            User.user_type == "client",
            User.status == "active",
            NotificationPreference.email_bulletins.is_(True),
        )
        .order_by(User.email)
    )
    return list(dict.fromkeys(rows.scalars()))


async def _visible_snapshot(db: AsyncSession, event: PublicationEvent) -> PublicationEvent | None:
    """For a withdrawal: the last published snapshot, whose readers are told."""
    if event.kind != "withdrawn":
        return event
    return (
        await db.execute(
            select(PublicationEvent)
            .where(
                PublicationEvent.bulletin_id == event.bulletin_id,
                PublicationEvent.kind.in_(("published", "updated")),
                PublicationEvent.at <= event.at,
            )
            .order_by(PublicationEvent.at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


def _messages(
    recipients: Iterable[str],
    event: PublicationEvent,
    revision: BulletinRevision | None,
    pdf: bytes | None,
    issuer: str,
    link: str,
) -> list[Mail]:
    label = {"published": "", "updated": "Mise à jour : ", "withdrawn": "Retrait : "}[event.kind]
    subject = f"[TLP:{event.tlp}] {label}{event.ref} — {event.title}"[:250]
    handling = HANDLING.get(event.tlp, "")
    if event.kind == "withdrawn" or revision is None:
        text = (
            f"{issuer}\n\nLe bulletin {event.ref} « {event.title} » a été retiré par "
            f"l'équipe {event.team}. Il n'est plus disponible sur le portail.\n"
        )
        return [Mail(to=r, subject=subject, body=text) for r in recipients]
    text = f"{issuer}\n{handling}\n\n{revision.rendered_markdown}\n\nSur le portail : {link}\n"
    html = (
        f'<!doctype html><html><body><p style="font-size:12px;color:#444">{escape(issuer)}</p>'
        f"<p><strong>{escape(handling)}</strong></p>{revision.rendered_html}"
        f'<p><a href="{escape(link)}">{escape(link)}</a></p></body></html>'
    )
    attachments = (
        (Attachment(f"{event.ref}.pdf", "application/pdf", pdf),) if pdf is not None else ()
    )
    return [
        Mail(to=r, subject=subject, body=text, html=html, attachments=attachments)
        for r in recipients
    ]


async def send_publication_mail(
    sessions: async_sessionmaker[AsyncSession],
    deps: MailDeps,
    event_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> int:
    """Sends the messages of one snapshot; returns how many were sent."""
    async with sessions() as db:
        init_context(db)
        await set_context(db, workspace_ids=(workspace_id,))
        event = await db.get(PublicationEvent, event_id, with_for_update=True)
        if event is None or event.notified_at is not None:
            return 0  # unknown, or already handled (at-least-once delivery)
        shown = await _visible_snapshot(db, event)
        recipients = await _recipients(db, shown) if shown is not None else []
        revision = (
            await db.get(BulletinRevision, event.revision_id)
            if event.revision_id and event.kind != "withdrawn"
            else None
        )
        branding = await db.get(PlatformBranding, 1)
        issuer = branding.issuer_name if branding and branding.issuer_name else "Vuln-Veille"
        first = (
            await db.execute(
                select(PublicationEvent.at)
                .where(
                    PublicationEvent.bulletin_id == event.bulletin_id,
                    PublicationEvent.kind == "published",
                )
                .order_by(PublicationEvent.at)
                .limit(1)
            )
        ).scalar_one_or_none() or event.at
        pdf = None
        if recipients and revision is not None:
            pdf = render_pdf(
                PdfBulletin(
                    ref=event.ref,
                    title=event.title,
                    severity=event.severity,
                    tlp=event.tlp,
                    team=event.team,
                    language=event.language,
                    published_at=first,
                    updated_at=event.at,
                    cves=list(event.cves),
                    technologies=[str(t.get("name", "")) for t in event.technologies],
                    html=revision.rendered_html,
                ),
                issuer,
                branding.logo_png if branding else None,
            )
        link = f"{str(deps.settings.portal_origin).rstrip('/')}/bulletins/{event.bulletin_id}"
        sent = 0
        for mail in _messages(recipients, event, revision, pdf, issuer, link):
            try:
                deps.send(mail)
                sent += 1
            except Exception:
                # The address is not logged; the snapshot and the count are.
                log.exception("publication_mail_failed", event_id=str(event_id))
        event.notified_at = deps.clock()
        await db.commit()
        log.info("publication_mail_sent", event_id=str(event_id), recipients=sent)
        return sent


async def publication_mail_entry(
    settings: Settings, event_id: uuid.UUID, workspace_id: uuid.UUID
) -> None:
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        deps = MailDeps(settings, lambda mail: deliver_smtp(settings, mail))
        await send_publication_mail(create_sessionmaker(engine), deps, event_id, workspace_id)
    finally:
        await engine.dispose()
