"""Global CVE catalogue, change history and event outbox (phase 2, steps 2.4-2.5).

``cve_records`` mirrors NVD (and early CVE.org records); ``cve_changes`` keeps the
timeline of detected changes; ``outbox_events`` carries ``cve.published`` and
``cve.updated``, written in the same transaction as the catalogue change.

The catalogue is shared by every internal user (read through the API with
``vuln.read``) and written only by the workers: ``vv_app`` may read it, and may
only append events to the outbox; the portal has no access.

Revision ID: 0005_catalog
Revises: 0004_connectors
Create Date: 2026-10-23 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0005_catalog"
down_revision: str | None = "0004_connectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = """
CREATE TABLE cve_records (
    cve_id text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    source_identifier text,
    published_at timestamptz,
    last_modified_at timestamptz,
    vuln_status text,
    description text NOT NULL DEFAULT '',
    cvss jsonb NOT NULL DEFAULT '{}',
    base_score numeric(3, 1) CHECK (base_score BETWEEN 0 AND 10),
    severity text CHECK (severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cwes text[] NOT NULL DEFAULT '{}',
    "references" jsonb NOT NULL DEFAULT '[]',
    cpe_configurations jsonb NOT NULL DEFAULT '[]',
    cpe_criteria text[] NOT NULL DEFAULT '{}',
    kev jsonb,
    epss_score numeric(6, 5),
    epss_percentile numeric(6, 5),
    epss_date timestamptz,
    sources text[] NOT NULL DEFAULT '{}',
    first_seen_at timestamptz NOT NULL,
    from_backfill boolean NOT NULL DEFAULT false,
    synced_at timestamptz NOT NULL
);
CREATE INDEX ix_cve_records_published_at ON cve_records (published_at DESC);
CREATE INDEX ix_cve_records_last_modified_at ON cve_records (last_modified_at DESC);
CREATE INDEX ix_cve_records_cpe_criteria ON cve_records USING gin (cpe_criteria);
CREATE INDEX ix_cve_records_description_trgm ON cve_records USING gin (description gin_trgm_ops);

CREATE TABLE cve_changes (
    id bigserial PRIMARY KEY,
    cve_id text NOT NULL REFERENCES cve_records (cve_id) ON DELETE CASCADE,
    detected_at timestamptz NOT NULL,
    change_types text[] NOT NULL CHECK (
        change_types <@ ARRAY['published', 'cvss_added', 'severity_raised', 'cpe_added',
                              'kev_added', 'exploit_reference_added', 'rejected']::text[]
        AND cardinality(change_types) > 0
    ),
    source text NOT NULL,
    diff jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_cve_changes_cve_id ON cve_changes (cve_id, detected_at DESC);

CREATE TABLE outbox_events (
    id bigserial PRIMARY KEY,
    type text NOT NULL CHECK (type ~ '^[a-z_]+\\.[a-z_]+$'),
    workspace_id uuid REFERENCES workspaces (id),
    payload jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    dispatched_at timestamptz,
    attempts integer NOT NULL DEFAULT 0
);
CREATE INDEX ix_outbox_events_pending ON outbox_events (id) WHERE dispatched_at IS NULL;
"""

GRANTS = """
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON cve_records, cve_changes FROM vv_app;
REVOKE ALL ON SEQUENCE cve_changes_id_seq FROM vv_app;
REVOKE UPDATE, DELETE, TRUNCATE ON outbox_events FROM vv_app;
REVOKE DELETE, TRUNCATE ON cve_records, cve_changes FROM vv_worker;
"""


def upgrade() -> None:
    for script in (TABLES, GRANTS):
        execute_script(script)


def downgrade() -> None:
    execute_script("DROP TABLE IF EXISTS outbox_events, cve_changes, cve_records;")
