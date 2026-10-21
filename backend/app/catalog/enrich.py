"""Catalogue enrichment from CISA KEV and FIRST EPSS (spec 07 §2).

- KEV marks a CVE as actively exploited: ``kev_added``, announced when the entry was
  added recently (the first import, a catch-up, announces nothing). A KEV entry for
  a CVE missing from the catalogue creates a minimal record that NVD completes later.
- EPSS only refreshes the exploitation probability of known CVEs (no event).
"""

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.models import CveRecord
from app.catalog.nvd_parse import CVE_ID
from app.catalog.store import Detected, record_change

KEV_SOURCE = "cisa_kev"


class KevEntry(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    cve_id: str = Field(alias="cveID", pattern=CVE_ID.pattern)
    vendor: str = Field(default="", alias="vendorProject", max_length=300)
    product: str = Field(default="", max_length=300)
    name: str = Field(default="", alias="vulnerabilityName", max_length=500)
    date_added: date = Field(alias="dateAdded")
    description: str = Field(default="", alias="shortDescription", max_length=5000)
    required_action: str = Field(default="", alias="requiredAction", max_length=2000)
    due_date: date | None = Field(default=None, alias="dueDate")
    ransomware: str = Field(default="Unknown", alias="knownRansomwareCampaignUse", max_length=20)
    cwes: list[str] = Field(default=[], max_length=20)

    def as_kev(self) -> dict[str, object]:
        return {
            "date_added": self.date_added.isoformat(),
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "required_action": self.required_action,
            "name": self.name,
            "vendor": self.vendor,
            "product": self.product,
            "ransomware": self.ransomware == "Known",
            "source": KEV_SOURCE,
        }


def parse_kev_feed(payload: object) -> tuple[str, list[KevEntry], int]:
    """(catalog version, valid entries, number of malformed entries)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("unexpected KEV feed")
    entries, malformed = [], 0
    for item in payload["vulnerabilities"]:
        try:
            entries.append(KevEntry.model_validate(item))
        except ValidationError:
            malformed += 1
    return str(payload.get("catalogVersion", ""))[:40], entries, malformed


async def apply_kev(
    db: AsyncSession,
    entries: list[KevEntry],
    *,
    now: datetime,
    announce: bool,
    announce_within: timedelta,
) -> int:
    """Applies the feed; returns how many CVEs became known-exploited. Caller commits."""
    added = 0
    for entry in entries:
        kev = entry.as_kev()
        record = await db.get(CveRecord, entry.cve_id, with_for_update=True)
        if record is None:
            record = CveRecord(
                cve_id=entry.cve_id,
                description=entry.description,
                cvss={},
                cwes=sorted({c for c in entry.cwes if c.startswith("CWE-")})[:20],
                references=[],
                cpe_configurations=[],
                cpe_criteria=[],
                sources=[KEV_SOURCE],
                kev=kev,
                first_seen_at=now,
                from_backfill=not announce,
                synced_at=now,
            )
            db.add(record)
            newly_exploited = True
        else:
            newly_exploited = record.kev is None
            record.kev = {**(record.kev or {}), **kev}
            if KEV_SOURCE not in record.sources:
                record.sources = [*record.sources, KEV_SOURCE]
        await db.flush()
        if newly_exploited:
            added += 1
            recent = now.date() - entry.date_added <= announce_within
            record_change(
                db,
                record,
                Detected(["kev_added"], {"kev": kev}),
                source=KEV_SOURCE,
                now=now,
                announce=announce and recent,
            )
    return added


class EpssScore(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    cve: str = Field(pattern=CVE_ID.pattern)
    epss: Decimal = Field(ge=0, le=1)
    percentile: Decimal = Field(ge=0, le=1)
    day: date = Field(alias="date")


async def apply_epss(db: AsyncSession, scores: list[EpssScore]) -> int:
    updated = 0
    for score in scores:
        result = await db.execute(
            update(CveRecord)
            .where(CveRecord.cve_id == score.cve)
            .values(
                epss_score=score.epss.quantize(Decimal("0.00001")),
                epss_percentile=score.percentile.quantize(Decimal("0.00001")),
                epss_date=datetime(score.day.year, score.day.month, score.day.day, tzinfo=UTC),
            )
        )
        updated += result.rowcount or 0  # type: ignore[attr-defined]
    return updated
