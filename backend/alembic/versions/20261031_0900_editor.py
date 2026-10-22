"""Visual editor support (phase 5, steps 5.4 and 5.6).

- ``workflow_drafts``: the version an analyst is editing, kept server side (one per
  workflow) until it is published as a version;
- test runs: a ``workflow_runs`` row in ``test`` mode carries the graph being edited,
  the node under test and its pinned inputs; only that node runs, in dry-run, and its
  database effects are rolled back. Test runs have no version.

Revision ID: 0014_editor
Revises: 0013_x_coverage
Create Date: 2026-10-31 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0014_editor"
down_revision: str | None = "0013_x_coverage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"

SCRIPT = f"""
ALTER TABLE workflow_runs ALTER COLUMN version_id DROP NOT NULL;
ALTER TABLE workflow_runs ADD COLUMN mode text NOT NULL DEFAULT 'normal'
    CHECK (mode IN ('normal', 'test'));
ALTER TABLE workflow_runs ADD COLUMN test_graph jsonb;
ALTER TABLE workflow_runs ADD COLUMN test_node_id text CHECK (length(test_node_id) <= 64);
ALTER TABLE workflow_runs ADD COLUMN test_inputs jsonb;
ALTER TABLE workflow_runs ADD CONSTRAINT ck_workflow_runs_mode CHECK (
    (mode = 'normal' AND version_id IS NOT NULL AND test_graph IS NULL)
    OR (mode = 'test' AND test_graph IS NOT NULL AND test_node_id IS NOT NULL)
);
CREATE INDEX ix_workflow_runs_tests ON workflow_runs (workflow_id, queued_at DESC)
    WHERE mode = 'test';

CREATE TABLE workflow_drafts (
    workflow_id uuid PRIMARY KEY REFERENCES workflows (id) ON DELETE CASCADE,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    graph jsonb NOT NULL,
    base_version_no integer,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON workflow_drafts FROM vv_worker;
ALTER TABLE workflow_drafts ENABLE ROW LEVEL SECURITY;
CREATE POLICY workflow_drafts_app ON workflow_drafts TO vv_app USING ({APP}) WITH CHECK ({APP});
"""


def upgrade() -> None:
    execute_script(SCRIPT)


def downgrade() -> None:
    execute_script(
        """
DROP TABLE IF EXISTS workflow_drafts;
DELETE FROM workflow_runs WHERE mode = 'test';
ALTER TABLE workflow_runs DROP CONSTRAINT ck_workflow_runs_mode;
ALTER TABLE workflow_runs DROP COLUMN test_inputs, DROP COLUMN test_node_id,
    DROP COLUMN test_graph, DROP COLUMN mode;
ALTER TABLE workflow_runs ALTER COLUMN version_id SET NOT NULL;
"""
    )
