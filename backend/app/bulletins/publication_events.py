"""Snapshots of what was published (spec 06, ADR-031): the portal's only source.

Taken in the transaction of a publication or a withdrawal, from the revision being
published and the marking, audience, CVEs and technologies as approved; later edits
of the bulletin (a draft update, a new TLP) reach clients only with the next
publication.
"""

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.bulletins.models import (
    Bulletin,
    BulletinAudience,
    BulletinRevision,
    BulletinTechnology,
    BulletinVulnerability,
    PublicationEvent,
)
from app.core.ids import uuid7
from app.iam.models import Workspace
from app.technologies.models import Technology
from app.vulns.models import Vulnerability


async def record_publication(
    db: AsyncSession, bulletin: Bulletin, kind: str, now: datetime
) -> PublicationEvent:
    """``kind``: ``publish`` (first publication or update) or ``withdrawn``."""
    revision = (
        await db.get(BulletinRevision, bulletin.published_revision_id)
        if bulletin.published_revision_id
        else None
    )
    earlier = await db.execute(
        select(PublicationEvent.id).where(PublicationEvent.bulletin_id == bulletin.id).limit(1)
    )
    if kind == "publish":
        kind = "updated" if earlier.first() is not None else "published"
    workspace = await db.get(Workspace, bulletin.workspace_id)
    fields = dict(revision.fields) if revision else {}
    orgs = (
        await db.execute(
            select(BulletinAudience.client_org_id).where(
                BulletinAudience.bulletin_id == bulletin.id
            )
        )
    ).scalars()
    cves = (
        await db.execute(
            select(Vulnerability.cve_id)
            .join(BulletinVulnerability, BulletinVulnerability.vulnerability_id == Vulnerability.id)
            .where(
                BulletinVulnerability.bulletin_id == bulletin.id, Vulnerability.cve_id.is_not(None)
            )
            .order_by(Vulnerability.cve_id)
        )
    ).scalars()
    technologies = (
        await db.execute(
            select(Technology)
            .join(BulletinTechnology, BulletinTechnology.technology_id == Technology.id)
            .where(BulletinTechnology.bulletin_id == bulletin.id)
            .order_by(Technology.display_name)
        )
    ).scalars()
    event = PublicationEvent(
        id=uuid7(),
        workspace_id=bulletin.workspace_id,
        bulletin_id=bulletin.id,
        revision_id=revision.id if revision else None,
        rev_no=revision.rev_no if revision else None,
        kind=kind,
        at=now,
        ref=bulletin.ref,
        language=bulletin.language,
        team=(workspace.slug if workspace else "").upper(),
        title=str(fields.get("title") or bulletin.title)[:300],
        severity=str(fields["severity"]) if fields.get("severity") else None,
        tlp=bulletin.tlp,
        audience_type=bulletin.audience_type,
        audience_org_ids=[uuid.UUID(str(o)) for o in orgs],
        cves=[c for c in cves if c],
        technologies=[
            {"vendor": t.vendor, "product": t.product, "name": t.display_name} for t in technologies
        ],
    )
    db.add(event)
    return event
