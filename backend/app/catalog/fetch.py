"""On-demand fetch of one CVE from NVD (manual entry of an identifier, spec 07 §3.5).

Run by the collect worker with the global NVD connector. A manual fetch announces
nothing: the analyst's ``vuln.created`` already launches the investigation.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.catalog.models import CveRecord
from app.catalog.nvd_parse import CVE_ID, NvdParseError, parse_cve
from app.catalog.store import upsert_cve
from app.connectors.models import Connector
from app.connectors.runtime import build_context
from app.connectors.types.nvd import NvdConnector, NvdError
from app.core.config import Settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import get_logger
from app.core.rls import init_context
from app.net.safe_http import EgressError, SafeHttpClient
from app.vault.service import Vault
from app.vulns.models import Vulnerability
from app.vulns.service import default_title, link_technologies_by_cpe

log = get_logger(__name__)


async def fetch_cve(settings: Settings, cve_id: str, *, http: SafeHttpClient | None = None) -> bool:
    """True when the CVE is in the catalogue afterwards."""
    if not CVE_ID.fullmatch(cve_id):
        return False
    engine = create_engine(settings.database_url_worker.get_secret_value())
    try:
        async with create_sessionmaker(engine)() as db:
            init_context(db)
            if await db.get(CveRecord, cve_id) is not None:
                return True
            connector = (
                await db.execute(
                    select(Connector)
                    .where(
                        Connector.kind == NvdConnector.kind,
                        Connector.workspace_id.is_(None),
                        Connector.enabled,
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            if connector is None:
                log.warning("cve_fetch_without_nvd_connector")
                return False
            try:
                _, ctx = await build_context(db, settings, Vault.from_settings(settings), connector)
                if http is not None:
                    ctx.http = http
                item = await NvdConnector.client(ctx).cve(cve_id)
                if item is None:
                    return False
                data = parse_cve(item)
            except (NvdError, EgressError, NvdParseError) as exc:
                log.warning("cve_fetch_failed", reason=type(exc).__name__)
                return False
            now = datetime.now(UTC)
            await upsert_cve(
                db, data, source="nvd", now=now, backfill=True, announce_within=timedelta(0)
            )
            vulnerability = (
                await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            ).scalar_one_or_none()
            if vulnerability is not None:
                record = await db.get(CveRecord, cve_id)
                if vulnerability.title == cve_id:
                    vulnerability.title = default_title(record, cve_id)
                await link_technologies_by_cpe(db, vulnerability, record)
            await db.commit()
            return True
    finally:
        await engine.dispose()
