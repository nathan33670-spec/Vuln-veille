"""Technology catalogue, watch scopes, watch sources, collected items (steps 2.7-2.9, 2.12).

- ``technologies`` is global (vendor + product granularity, Q20), searchable with
  trigrams; analysts curate it, administrators merge and delete.
- ``watch_scopes`` (one per workspace) decides which new CVEs launch an investigation.
- ``watch_sources`` lists the feeds and accounts a workspace follows.
- ``collected_items`` stores what agents and workflows read: always untrusted, bounded,
  de-duplicated per workspace by content hash.

Workspace tables carry RLS on ``app.workspace_ids`` for both the API and the workers.

Revision ID: 0006_watch
Revises: 0005_catalog
Create Date: 2026-10-23 14:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0006_watch"
down_revision: str | None = "0005_catalog"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
IN_WORKSPACE = f"workspace_id = ANY ({CTX_WORKSPACES})"

TABLES = """
CREATE TABLE technologies (
    id uuid PRIMARY KEY,
    vendor text NOT NULL CHECK (vendor ~ '^[a-z0-9][a-z0-9._+-]{0,99}$'),
    product text NOT NULL CHECK (product ~ '^[a-z0-9][a-z0-9._+-]{0,99}$'),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    aliases text[] NOT NULL DEFAULT '{}',
    cpe_prefixes text[] NOT NULL DEFAULT '{}',
    purls text[] NOT NULL DEFAULT '{}',
    category text NOT NULL DEFAULT '' CHECK (length(category) <= 100),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deprecated', 'merged')),
    merged_into uuid REFERENCES technologies (id),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_technologies_vendor_product UNIQUE (vendor, product),
    CONSTRAINT ck_technologies_merged CHECK ((status = 'merged') = (merged_into IS NOT NULL))
);
CREATE INDEX ix_technologies_search ON technologies
    USING gin ((display_name || ' ' || vendor || ' ' || product) gin_trgm_ops);
CREATE INDEX ix_technologies_cpe ON technologies USING gin (cpe_prefixes);

CREATE TABLE watch_scopes (
    workspace_id uuid PRIMARY KEY REFERENCES workspaces (id),
    mode text NOT NULL DEFAULT 'scoped' CHECK (mode IN ('all', 'scoped')),
    technology_ids uuid[] NOT NULL DEFAULT '{}',
    vendors text[] NOT NULL DEFAULT '{}',
    keywords text[] NOT NULL DEFAULT '{}',
    cvss_min numeric(3, 1) CHECK (cvss_min BETWEEN 0 AND 10),
    include_unscored text NOT NULL DEFAULT 'wait'
        CHECK (include_unscored IN ('include', 'wait', 'exclude')),
    always_include_kev boolean NOT NULL DEFAULT true,
    cwe_include text[] NOT NULL DEFAULT '{}',
    cwe_exclude text[] NOT NULL DEFAULT '{}',
    version integer NOT NULL DEFAULT 1,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE watch_sources (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    type text NOT NULL,
    config jsonb NOT NULL DEFAULT '{}',
    tags text[] NOT NULL DEFAULT '{}',
    trust_level text NOT NULL DEFAULT 'medium' CHECK (trust_level IN ('low', 'medium', 'high')),
    enabled boolean NOT NULL DEFAULT true,
    version integer NOT NULL DEFAULT 1,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_watch_sources_name UNIQUE (workspace_id, name)
);

CREATE TABLE collected_items (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    run_id uuid,
    node_id text,
    source_type text NOT NULL CHECK (length(source_type) BETWEEN 1 AND 40),
    source_ref text NOT NULL DEFAULT '' CHECK (length(source_ref) <= 500),
    url text CHECK (url IS NULL OR (url ~ '^https?://' AND length(url) <= 2048)),
    url_hash text,
    title text NOT NULL DEFAULT '' CHECK (length(title) <= 500),
    content_text text NOT NULL DEFAULT '' CHECK (length(content_text) <= 100000),
    author text NOT NULL DEFAULT '' CHECK (length(author) <= 200),
    published_at timestamptz,
    fetched_at timestamptz NOT NULL,
    content_hash text NOT NULL,
    cve_ids text[] NOT NULL DEFAULT '{}',
    language text NOT NULL DEFAULT '' CHECK (length(language) <= 10),
    raw jsonb NOT NULL DEFAULT '{}',
    trust text NOT NULL DEFAULT 'untrusted' CHECK (trust = 'untrusted'),
    CONSTRAINT uq_collected_items_content UNIQUE (workspace_id, content_hash)
);
CREATE INDEX ix_collected_items_cve_ids ON collected_items USING gin (cve_ids);
CREATE INDEX ix_collected_items_url_hash ON collected_items (workspace_id, url_hash);
"""

GRANTS = """
REVOKE DELETE, TRUNCATE ON technologies FROM vv_worker;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON watch_scopes, watch_sources FROM vv_worker;
"""

POLICIES = f"""
ALTER TABLE watch_scopes ENABLE ROW LEVEL SECURITY;
CREATE POLICY watch_scopes_scope ON watch_scopes TO vv_app, vv_worker
    USING ({IN_WORKSPACE}) WITH CHECK ({IN_WORKSPACE});
ALTER TABLE watch_sources ENABLE ROW LEVEL SECURITY;
CREATE POLICY watch_sources_scope ON watch_sources TO vv_app, vv_worker
    USING ({IN_WORKSPACE}) WITH CHECK ({IN_WORKSPACE});
ALTER TABLE collected_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY collected_items_scope ON collected_items TO vv_app, vv_worker
    USING ({IN_WORKSPACE}) WITH CHECK ({IN_WORKSPACE});
"""


def upgrade() -> None:
    for script in (TABLES, GRANTS, POLICIES):
        execute_script(script)


def downgrade() -> None:
    execute_script(
        "DROP TABLE IF EXISTS collected_items, watch_sources, watch_scopes, technologies;"
    )
