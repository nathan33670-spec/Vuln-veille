"""Catalogue updates and change detection (spec 07 §3.2).

Each incoming record is compared with the known one, in a row-locked transaction:
the record, its change history (``cve_changes``) and the announcing event
(``outbox_events``) are written together, or not at all. Re-applying the same data
detects nothing, so a sync window can always be replayed safely.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.models import CveChange, CveRecord, OutboxEvent
from app.catalog.nvd_parse import SEVERITY_RANK, CveData

MAX_DIFF_ITEMS = 50


@dataclass(frozen=True)
class Detected:
    change_types: list[str]
    diff: dict[str, Any]


def _scored(cvss: dict[str, list[dict[str, Any]]]) -> set[tuple[str, str]]:
    return {
        (version, m["source"]) for version, ms in cvss.items() for m in ms if m["score"] is not None
    }


def _exploit_urls(references: list[dict[str, Any]]) -> set[str]:
    return {r["url"] for r in references if "Exploit" in r.get("tags", [])}


def detect(old: CveRecord | None, new: CveData) -> Detected:
    if old is None:
        return Detected(
            ["published"], {"severity": new.severity, "base_score": _num(new.base_score)}
        )
    types: list[str] = []
    diff: dict[str, Any] = {}
    if _scored(new.cvss) - _scored(old.cvss):
        types.append("cvss_added")
    old_rank = SEVERITY_RANK.get(old.severity or "", -1)
    if old.severity and SEVERITY_RANK.get(new.severity or "", -1) > old_rank:
        types.append("severity_raised")
    if types:
        diff["cvss"] = {
            "before": {"severity": old.severity, "base_score": _num(old.base_score)},
            "after": {"severity": new.severity, "base_score": _num(new.base_score)},
        }
    added_cpe = sorted(set(new.cpe_criteria) - set(old.cpe_criteria))
    if added_cpe:
        types.append("cpe_added")
        diff["cpe_added"] = added_cpe[:MAX_DIFF_ITEMS]
    if new.kev is not None and old.kev is None:
        types.append("kev_added")
        diff["kev"] = new.kev
    exploits = sorted(new.exploit_urls - _exploit_urls(old.references))
    if exploits:
        types.append("exploit_reference_added")
        diff["exploit_references_added"] = exploits[:MAX_DIFF_ITEMS]
    if new.vuln_status == "Rejected" and old.vuln_status != "Rejected":
        types.append("rejected")
    return Detected(types, diff)


def _num(value: object) -> float | None:
    return float(value) if value is not None else None  # type: ignore[arg-type]


async def upsert_cve(
    db: AsyncSession,
    data: CveData,
    *,
    source: str,
    now: datetime,
    backfill: bool,
    announce_within: timedelta,
) -> Detected:
    """Applies one record; returns what changed. The caller commits.

    A record never seen before is announced (``cve.published``) only if it was
    published recently: an old CVE modified today is catalogued silently.
    """
    old = await db.get(CveRecord, data.cve_id, with_for_update=True)
    detected = detect(old, data)
    record = old
    if record is None:
        record = CveRecord(
            cve_id=data.cve_id, first_seen_at=now, from_backfill=backfill, sources=[], kev=None
        )
        db.add(record)
    record.source_identifier = data.source_identifier
    record.published_at = data.published_at
    record.last_modified_at = data.last_modified_at
    record.vuln_status = data.vuln_status
    record.description = data.description
    record.cvss = data.cvss
    record.base_score = data.base_score
    record.severity = data.severity
    record.cwes = data.cwes
    record.references = data.references
    record.cpe_configurations = data.cpe_configurations
    record.cpe_criteria = data.cpe_criteria
    if data.kev is not None:  # merged: NVD never erases what the CISA KEV feed provided
        record.kev = {**(record.kev or {}), **data.kev}
    if source not in record.sources:
        record.sources = [*record.sources, source]
    record.synced_at = now
    await db.flush()  # the record exists before its history and events reference it

    if detected.change_types:
        record_change(
            db,
            record,
            detected,
            source=source,
            now=now,
            announce=_announced(
                detected, data, now, backfill=backfill, announce_within=announce_within
            ),
        )
    return detected


def record_change(
    db: AsyncSession,
    record: CveRecord,
    detected: Detected,
    *,
    source: str,
    now: datetime,
    announce: bool,
) -> None:
    """History entry, plus the outbox event when the change is announced."""
    db.add(
        CveChange(
            cve_id=record.cve_id,
            detected_at=now,
            change_types=detected.change_types,
            source=source,
            diff=detected.diff,
        )
    )
    if announce:
        published = detected.change_types == ["published"]
        db.add(
            OutboxEvent(
                type="cve.published" if published else "cve.updated",
                payload={
                    "cve_id": record.cve_id,
                    "change_types": detected.change_types,
                    "source": source,
                    "severity": record.severity,
                    "base_score": _num(record.base_score),
                },
                created_at=now,
                attempts=0,
            )
        )


def _announced(
    detected: Detected, data: CveData, now: datetime, *, backfill: bool, announce_within: timedelta
) -> bool:
    if backfill:
        return False
    if detected.change_types == ["published"]:
        return data.published_at is not None and now - data.published_at <= announce_within
    return True
