"""Connector framework (phase 2, step 2.3).

``connectors`` holds the configuration of every access to an external service
(families source, ai_engine, publish; global when ``workspace_id`` is NULL).
``connector_cursors`` keeps synchronisation positions (written by the workers).

RLS, as for secrets: ``vv_app`` sees global connectors only as platform admin and
workspace connectors only for its request workspaces; ``vv_worker`` reads global
connectors and those of its task's workspaces, updates health and usage, and never
creates or deletes connectors.

Revision ID: 0004_connectors
Revises: 0003_vault
Create Date: 2026-10-22 14:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0004_connectors"
down_revision: str | None = "0003_vault"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP_SCOPE = f"(workspace_id IS NULL AND {CTX_ADMIN}) OR workspace_id = ANY ({CTX_WORKSPACES})"
WORKER_SCOPE = f"workspace_id IS NULL OR workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN}"

TABLES = """
CREATE TABLE connectors (
    id uuid PRIMARY KEY,
    workspace_id uuid REFERENCES workspaces (id),
    family text NOT NULL CHECK (family IN ('source', 'ai_engine', 'publish')),
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{1,31}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    config jsonb NOT NULL DEFAULT '{}',
    secret_refs jsonb NOT NULL DEFAULT '{}',
    quotas jsonb NOT NULL DEFAULT '{}',
    usage_current_period jsonb NOT NULL DEFAULT '{}',
    egress_domains text[] NOT NULL DEFAULT '{}',
    allow_private_network boolean NOT NULL DEFAULT false,
    private_network_cidrs cidr[] NOT NULL DEFAULT '{}',
    private_network_approved_by uuid REFERENCES users (id) ON DELETE SET NULL,
    private_network_approved_at timestamptz,
    data_policy jsonb NOT NULL DEFAULT '{}',
    last_check_at timestamptz,
    last_success_at timestamptz,
    last_error text CHECK (length(last_error) <= 500),
    consecutive_failures integer NOT NULL DEFAULT 0,
    enabled boolean NOT NULL DEFAULT true,
    version integer NOT NULL DEFAULT 1,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_connectors_workspace_name UNIQUE NULLS NOT DISTINCT (workspace_id, name),
    CONSTRAINT ck_connectors_private_network
        CHECK (allow_private_network OR cardinality(private_network_cidrs) = 0)
);
CREATE INDEX ix_connectors_workspace_family ON connectors (workspace_id, family);
CREATE INDEX ix_connectors_secret_refs ON connectors USING gin (secret_refs jsonb_path_ops);

CREATE TABLE connector_cursors (
    connector_id uuid NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    stream text NOT NULL CHECK (length(stream) BETWEEN 1 AND 64),
    position jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, stream)
);
"""

GRANTS = """
REVOKE INSERT, DELETE, TRUNCATE ON connectors FROM vv_worker;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON connector_cursors FROM vv_app;
"""

POLICIES = f"""
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
CREATE POLICY connectors_app ON connectors TO vv_app
    USING ({APP_SCOPE}) WITH CHECK ({APP_SCOPE});
CREATE POLICY connectors_worker ON connectors TO vv_worker
    USING ({WORKER_SCOPE}) WITH CHECK ({WORKER_SCOPE});

ALTER TABLE connector_cursors ENABLE ROW LEVEL SECURITY;
CREATE POLICY connector_cursors_app ON connector_cursors FOR SELECT TO vv_app
    USING (connector_id IN (SELECT id FROM connectors));
CREATE POLICY connector_cursors_worker ON connector_cursors TO vv_worker
    USING (connector_id IN (SELECT id FROM connectors))
    WITH CHECK (connector_id IN (SELECT id FROM connectors));
"""


def upgrade() -> None:
    for script in (TABLES, GRANTS, POLICIES):
        execute_script(script)


def downgrade() -> None:
    execute_script("DROP TABLE IF EXISTS connector_cursors, connectors;")
