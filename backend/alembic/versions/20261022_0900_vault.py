"""Secret vault (phase 2, step 2.1).

One row per secret: AES-256-GCM ciphertext under its own data key, the data key
wrapped for the purpose's X25519 public key (ADR-013). ``workspace_id`` NULL means a
global secret (platform connectors), managed by administrators only.

RLS model:
- ``vv_app`` sees global secrets only as platform admin, and workspace secrets only
  for its request workspaces: a VOC administrator never sees CERT secrets;
- ``vv_worker`` reads global secrets and those of its task's workspaces, and may only
  update them (key rotation); it never creates or deletes secrets;
- ``vv_portal`` has no access at all.

Revision ID: 0003_vault
Revises: 0002_iam
Create Date: 2026-10-22 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0003_vault"
down_revision: str | None = "0002_iam"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same request-context helpers as 0002 (migrations stay self-contained).
CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"

TABLES = """
CREATE TABLE secrets (
    id uuid PRIMARY KEY,
    workspace_id uuid REFERENCES workspaces (id),
    purpose text NOT NULL CHECK (purpose IN ('llm', 'source', 'connector', 'webhook')),
    name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL CHECK (length(nonce) = 12),
    dek_enc bytea NOT NULL,
    kek_id text NOT NULL,
    hint_last4 text NOT NULL DEFAULT '' CHECK (length(hint_last4) <= 4),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    value_updated_at timestamptz NOT NULL,
    rotated_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_secrets_workspace_name UNIQUE NULLS NOT DISTINCT (workspace_id, name),
    CONSTRAINT ck_secrets_global_purpose
        CHECK (workspace_id IS NOT NULL OR purpose IN ('llm', 'source'))
);
CREATE INDEX ix_secrets_kek_id ON secrets (purpose, kek_id);
"""

GRANTS = """
REVOKE INSERT, DELETE, TRUNCATE ON secrets FROM vv_worker;
"""

POLICIES = f"""
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY secrets_app ON secrets TO vv_app
    USING ((workspace_id IS NULL AND {CTX_ADMIN}) OR workspace_id = ANY ({CTX_WORKSPACES}))
    WITH CHECK ((workspace_id IS NULL AND {CTX_ADMIN}) OR workspace_id = ANY ({CTX_WORKSPACES}));
CREATE POLICY secrets_worker ON secrets TO vv_worker
    USING (workspace_id IS NULL OR workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN})
    WITH CHECK (workspace_id IS NULL OR workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN});
"""


def upgrade() -> None:
    for script in (TABLES, GRANTS, POLICIES):
        execute_script(script)


def downgrade() -> None:
    execute_script("DROP TABLE IF EXISTS secrets;")
