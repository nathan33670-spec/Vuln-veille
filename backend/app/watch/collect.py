"""Storing collected content (spec 01 §4): untrusted by construction.

Text is bounded and stripped of control characters; nothing is ever rendered as
markup, interpreted as a template or followed as an instruction. Items are
de-duplicated per workspace by a hash of their normalised URL and content.
"""

import hashlib
import json
import re
import unicodedata
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ids import uuid7
from app.watch.models import CollectedItem

MAX_TITLE = 500
MAX_CONTENT = 100_000
MAX_AUTHOR = 200
MAX_RAW_BYTES = 64 * 1024
CVE_MENTION = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def clean_text(value: str | None, limit: int) -> str:
    """NFC, no control or bidirectional override characters, bounded."""
    if not value:
        return ""
    return _CONTROL.sub("", unicodedata.normalize("NFC", value))[:limit]


def normalize_url(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("only http(s) URLs are collected")
    netloc = parts.hostname.lower() + (f":{parts.port}" if parts.port else "")
    normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    if len(normalized) > 2048:  # noqa: PLR2004
        raise ValueError("URL too long")
    return normalized


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def store_item(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    *,
    source_type: str,
    now: datetime,
    url: str | None = None,
    title: str | None = None,
    content: str | None = None,
    author: str | None = None,
    published_at: datetime | None = None,
    source_ref: str = "",
    raw: dict[str, Any] | None = None,
    run_id: uuid.UUID | None = None,
    node_id: str | None = None,
) -> tuple[CollectedItem, bool]:
    """Returns the stored item and whether it is new."""
    normalized = normalize_url(url)
    title_text = clean_text(title, MAX_TITLE)
    content_text = clean_text(content, MAX_CONTENT)
    content_hash = _sha("\n".join((normalized or "", title_text, content_text)))
    raw_value = raw or {}
    if len(json.dumps(raw_value, default=str)) > MAX_RAW_BYTES:
        raw_value = {"truncated": True}
    mentions = sorted({m.upper() for m in CVE_MENTION.findall(f"{title_text}\n{content_text}")})
    values = {
        "id": uuid7(),
        "workspace_id": workspace_id,
        "run_id": run_id,
        "node_id": node_id,
        "source_type": source_type[:40],
        "source_ref": clean_text(source_ref, 500),
        "url": normalized,
        "url_hash": _sha(normalized) if normalized else None,
        "title": title_text,
        "content_text": content_text,
        "author": clean_text(author, MAX_AUTHOR),
        "published_at": published_at,
        "fetched_at": now,
        "content_hash": content_hash,
        "cve_ids": mentions[:200],
        "raw": raw_value,
        "trust": "untrusted",
    }
    inserted = await db.execute(
        insert(CollectedItem)
        .values(**values)
        .on_conflict_do_nothing(index_elements=["workspace_id", "content_hash"])
        .returning(CollectedItem.id)
    )
    new_id = inserted.scalar_one_or_none()
    item = (
        await db.execute(
            select(CollectedItem).where(
                CollectedItem.workspace_id == workspace_id,
                CollectedItem.content_hash == content_hash,
            )
        )
    ).scalar_one()
    return item, new_id is not None
