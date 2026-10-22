"""Bulletin lifecycle (spec 04 §4, ADR-019, Q4).

``draft`` → (``in_review`` when the workspace requires a second analyst) → ``approved``
→ ``published`` → ``withdrawn``. Any edit of a submitted, approved or published bulletin
sends it back to ``draft``: what is approved and published is always the current
revision. A published bulletin keeps its published revision visible while its update
goes through the same steps again.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException

from app.bulletins.models import Bulletin


def conflict(code: str) -> HTTPException:
    return HTTPException(status_code=409, detail=code)


def ensure_editable(bulletin: Bulletin) -> None:
    if bulletin.status == "withdrawn":
        raise conflict("bulletin_withdrawn")


def after_edit(bulletin: Bulletin) -> None:
    """A new revision: whatever was submitted, approved or published is reviewed again."""
    if bulletin.status in ("in_review", "approved", "published"):
        bulletin.status = "draft"
        bulletin.submitted_by = None
        bulletin.reviewer_id = None
        bulletin.approved_at = None


@dataclass(frozen=True)
class Actor:
    user_id: uuid.UUID
    review_required: bool


def submit(bulletin: Bulletin, actor: Actor) -> None:
    if not actor.review_required:
        raise conflict("review_not_required")
    if bulletin.status != "draft":
        raise conflict("not_a_draft")
    bulletin.status = "in_review"
    bulletin.submitted_by = actor.user_id


def reject(bulletin: Bulletin, actor: Actor) -> None:
    if bulletin.status != "in_review":
        raise conflict("not_in_review")
    bulletin.status = "draft"
    bulletin.reviewer_id = actor.user_id
    bulletin.submitted_by = None


def approve(bulletin: Bulletin, actor: Actor, now: datetime) -> None:
    if actor.review_required:
        if bulletin.status != "in_review":
            raise conflict("not_in_review")
        # Double validation: the reviewer is neither the one who submitted, nor the author.
        if actor.user_id in (bulletin.submitted_by, bulletin.author_id):
            raise HTTPException(status_code=403, detail="reviewer_must_differ")
    elif bulletin.status not in ("draft", "in_review"):
        raise conflict("not_a_draft")
    bulletin.status = "approved"
    bulletin.reviewer_id = actor.user_id
    bulletin.approved_at = now


def publish(bulletin: Bulletin, actor: Actor, now: datetime) -> None:
    if bulletin.status != "approved":
        raise conflict("not_approved")
    bulletin.status = "published"
    bulletin.published_revision_id = bulletin.current_revision_id
    bulletin.published_at = now
    bulletin.published_by = actor.user_id


def withdraw(bulletin: Bulletin, reason: str, now: datetime) -> None:
    if bulletin.published_revision_id is None or bulletin.status == "withdrawn":
        raise conflict("not_published")
    bulletin.status = "withdrawn"
    bulletin.withdrawn_at = now
    bulletin.withdrawn_reason = reason
