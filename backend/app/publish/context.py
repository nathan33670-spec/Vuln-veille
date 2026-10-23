"""What a publication sends: the bulletin as validated, and nothing else (spec 05 §2).

A bulletin is pushable once approved (its current revision) or published (its
published revision, even while an update goes through review). The context holds
publishable data only: the bulletin, the revision's fields and rendering, the linked
CVEs and technologies. Never an internal qualification, a comment or a secret.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.bulletins.models import (
    Bulletin,
    BulletinRevision,
    BulletinSettings,
    BulletinTechnology,
    BulletinVulnerability,
)
from app.iam.models import Workspace
from app.technologies.models import Technology
from app.vulns.models import Vulnerability

PUSHABLE = frozenset({"approved", "published"})


class PublishError(ValueError):
    """A publication refused before any request; ``code`` is stable and shown as is."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Publication:
    bulletin: Bulletin
    revision: BulletinRevision
    vulnerabilities: list[Vulnerability]
    technologies: list[Technology]
    workspace_slug: str
    settings: BulletinSettings | None


def pushable_revision_id(bulletin: Bulletin) -> uuid.UUID | None:
    if bulletin.status == "approved":
        return bulletin.current_revision_id
    if bulletin.status == "published":
        return bulletin.published_revision_id
    return None


async def load_publication(
    db: AsyncSession, workspace_id: uuid.UUID, bulletin_id: uuid.UUID
) -> Publication:
    bulletin = await db.get(Bulletin, bulletin_id)
    if bulletin is None or bulletin.workspace_id != workspace_id:
        raise PublishError("bulletin_not_found")
    revision_id = pushable_revision_id(bulletin)
    if revision_id is None:
        raise PublishError("not_pushable")
    revision = await db.get(BulletinRevision, revision_id)
    if revision is None:
        raise PublishError("not_pushable")
    vulnerabilities = (
        await db.execute(
            select(Vulnerability)
            .join(BulletinVulnerability, BulletinVulnerability.vulnerability_id == Vulnerability.id)
            .where(BulletinVulnerability.bulletin_id == bulletin.id)
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
    workspace = await db.get(Workspace, workspace_id)
    return Publication(
        bulletin=bulletin,
        revision=revision,
        vulnerabilities=list(vulnerabilities),
        technologies=list(technologies),
        workspace_slug=workspace.slug if workspace else "",
        settings=await db.get(BulletinSettings, workspace_id),
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def publication_context(publication: Publication, remote_id: str | None = None) -> dict[str, Any]:
    """The data a mapping reads (JMESPath paths and Liquid templates)."""
    b, r = publication.bulletin, publication.revision
    fields = dict(r.fields)
    return {
        "bulletin": {
            "id": str(b.id),
            "ref": b.ref,
            "title": fields.get("title") or b.title,
            "language": b.language,
            "severity": b.severity,
            "tlp": b.tlp,
            "status": b.status,
            "published_at": _iso(b.published_at),
            "approved_at": _iso(b.approved_at),
            "updated_at": _iso(r.created_at),
            "team": publication.workspace_slug.upper(),
            "fields": fields,
        },
        "revision": {
            "rev_no": r.rev_no,
            "content_hash": r.content_hash,
            "created_at": _iso(r.created_at),
            "markdown": r.rendered_markdown,
            "html": r.rendered_html,
        },
        "cves": [v.cve_id for v in publication.vulnerabilities if v.cve_id],
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "ref": v.ref,
                "title": v.title,
                "exploitation_status": v.exploitation_status,
                "patch_status": v.patch_status,
            }
            for v in publication.vulnerabilities
        ],
        "technologies": [
            {"vendor": t.vendor, "product": t.product, "name": t.display_name}
            for t in publication.technologies
        ],
        "remote_id": remote_id,
    }


def sample_context() -> dict[str, Any]:
    """A fictitious context for the mapping editor before a bulletin is chosen."""
    return {
        "bulletin": {
            "id": "00000000-0000-0000-0000-000000000000",
            "ref": "VOC-2026-0001",
            "title": "Exécution de code à distance dans Exemple Serveur",
            "language": "fr",
            "severity": "critical",
            "tlp": "GREEN",
            "status": "published",
            "published_at": "2026-10-22T08:00:00+00:00",
            "approved_at": "2026-10-22T07:55:00+00:00",
            "updated_at": "2026-10-22T07:50:00+00:00",
            "team": "VOC",
            "fields": {
                "title": "Exécution de code à distance dans Exemple Serveur",
                "severity": "critical",
                "cves": ["CVE-2026-0001"],
                "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                "summary": "Une vulnérabilité permet l'exécution de code sans authentification.",
                "affected_products": [
                    {"vendor": "exemple", "product": "serveur", "versions": "< 2.4.1"}
                ],
                "recommendations": "Appliquer la version 2.4.1.",
                "references": [
                    {"title": "Avis de l'éditeur", "url": "https://exemple.org/avis/2026-01"}
                ],
            },
        },
        "revision": {
            "rev_no": 2,
            "content_hash": "0" * 64,
            "created_at": "2026-10-22T07:50:00+00:00",
            "markdown": "# Exécution de code à distance dans Exemple Serveur\n",
            "html": "<h1>Exécution de code à distance dans Exemple Serveur</h1>\n",
        },
        "cves": ["CVE-2026-0001"],
        "vulnerabilities": [
            {
                "cve_id": "CVE-2026-0001",
                "ref": "VV-2026-0001",
                "title": "Exécution de code dans Exemple Serveur",
                "exploitation_status": "exploited_itw",
                "patch_status": "available",
            }
        ],
        "technologies": [{"vendor": "exemple", "product": "serveur", "name": "Exemple Serveur"}],
        "remote_id": None,
    }
