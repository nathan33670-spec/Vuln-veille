"""AI engines: model catalogue with verified capabilities, preferred engine (phase 4,
steps 4.4-4.5).

- ``ai_models``: one row per model declared by an ``ai_engine`` connector. Declared
  capabilities are written when the connector is saved; verified ones by the
  connector test (worker). Models of global engines are readable by every internal
  user (a CERT analyst picks among them); writes follow the connector's scope.
- ``ai_engine_preferences``: the preferred engine of the platform (``workspace_id``
  null, platform administrators) and its override per workspace.

Revision ID: 0009_ai_engines
Revises: 0008_workflows
Create Date: 2026-10-26 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0009_ai_engines"
down_revision: str | None = "0008_workflows"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
READ = f"workspace_id IS NULL OR workspace_id = ANY ({CTX_WORKSPACES})"
WRITE = f"(workspace_id IS NULL AND {CTX_ADMIN}) OR workspace_id = ANY ({CTX_WORKSPACES})"
WORKER = f"workspace_id IS NULL OR workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN}"

TABLES = """
CREATE TABLE ai_models (
    id uuid PRIMARY KEY,
    connector_id uuid NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    workspace_id uuid REFERENCES workspaces (id),
    connector_kind text NOT NULL,
    connector_name text NOT NULL,
    connector_enabled boolean NOT NULL DEFAULT true,
    model_id text NOT NULL CHECK (model_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$'),
    display_name text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    declared jsonb NOT NULL DEFAULT '{}',
    verified jsonb,
    checks jsonb NOT NULL DEFAULT '{}',
    verified_at timestamptz,
    data_classes text[] NOT NULL DEFAULT '{}',
    location text NOT NULL CHECK (location IN ('external_cloud', 'self_hosted')),
    price_input_per_mtok numeric(10, 4),
    price_output_per_mtok numeric(10, 4),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_models_connector_model UNIQUE (connector_id, model_id)
);

CREATE TABLE ai_engine_preferences (
    id uuid PRIMARY KEY,
    workspace_id uuid REFERENCES workspaces (id),
    model_row_id uuid NOT NULL REFERENCES ai_models (id) ON DELETE CASCADE,
    changed_by uuid REFERENCES users (id) ON DELETE SET NULL,
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_ai_engine_preferences_platform ON ai_engine_preferences ((1))
    WHERE workspace_id IS NULL;
CREATE UNIQUE INDEX uq_ai_engine_preferences_workspace ON ai_engine_preferences (workspace_id)
    WHERE workspace_id IS NOT NULL;
"""

GRANTS = """
REVOKE TRUNCATE ON ai_models, ai_engine_preferences FROM vv_app, vv_worker;
REVOKE INSERT, DELETE ON ai_models FROM vv_worker;
REVOKE INSERT, UPDATE, DELETE ON ai_engine_preferences FROM vv_worker;
"""

POLICIES = f"""
ALTER TABLE ai_models ENABLE ROW LEVEL SECURITY;
CREATE POLICY ai_models_read ON ai_models FOR SELECT TO vv_app USING ({READ});
CREATE POLICY ai_models_insert ON ai_models FOR INSERT TO vv_app WITH CHECK ({WRITE});
CREATE POLICY ai_models_update ON ai_models FOR UPDATE TO vv_app
    USING ({WRITE}) WITH CHECK ({WRITE});
CREATE POLICY ai_models_delete ON ai_models FOR DELETE TO vv_app USING ({WRITE});
CREATE POLICY ai_models_worker ON ai_models TO vv_worker USING ({WORKER}) WITH CHECK ({WORKER});

ALTER TABLE ai_engine_preferences ENABLE ROW LEVEL SECURITY;
CREATE POLICY ai_engine_preferences_read ON ai_engine_preferences FOR SELECT TO vv_app
    USING ({READ});
CREATE POLICY ai_engine_preferences_insert ON ai_engine_preferences FOR INSERT TO vv_app
    WITH CHECK ({WRITE});
CREATE POLICY ai_engine_preferences_update ON ai_engine_preferences FOR UPDATE TO vv_app
    USING ({WRITE}) WITH CHECK ({WRITE});
CREATE POLICY ai_engine_preferences_delete ON ai_engine_preferences FOR DELETE TO vv_app
    USING ({WRITE});
CREATE POLICY ai_engine_preferences_worker ON ai_engine_preferences FOR SELECT TO vv_worker
    USING ({WORKER});
"""


def upgrade() -> None:
    for script in (TABLES, GRANTS, POLICIES):
        execute_script(script)


def downgrade() -> None:
    execute_script("DROP TABLE IF EXISTS ai_engine_preferences, ai_models;")
