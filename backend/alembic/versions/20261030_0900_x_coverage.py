"""X discovery through the engine's web search, and the X coverage indicator (phase 4,
step 4.18).

- ``ai_models.price_web_search_per_k``: what the engine bills for its web searches
  (Claude), counted in the estimated cost; the free tier (Gemini) declares none;
- ``x_coverage_checks``: CVEs whose X discussions an analyst checked by hand, the
  sample the indicator is compared with.

Revision ID: 0013_x_coverage
Revises: 0012_ai_evaluation
Create Date: 2026-10-30 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0013_x_coverage"
down_revision: str | None = "0012_ai_evaluation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"

SCRIPT = f"""
ALTER TABLE ai_models ADD COLUMN price_web_search_per_k numeric(10, 4);

CREATE TABLE x_coverage_checks (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{{4}}-[0-9]{{4,19}}$'),
    has_discussion boolean NOT NULL,
    urls text[] NOT NULL DEFAULT '{{}}' CHECK (cardinality(urls) <= 20),
    notes text NOT NULL DEFAULT '' CHECK (length(notes) <= 1000),
    checked_by uuid REFERENCES users (id) ON DELETE SET NULL,
    checked_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_x_coverage_checks UNIQUE (workspace_id, cve_id)
);
REVOKE ALL ON x_coverage_checks FROM vv_worker;
ALTER TABLE x_coverage_checks ENABLE ROW LEVEL SECURITY;
CREATE POLICY x_coverage_checks_app ON x_coverage_checks TO vv_app
    USING ({APP}) WITH CHECK ({APP});
"""


def upgrade() -> None:
    execute_script(SCRIPT)


def downgrade() -> None:
    execute_script(
        "DROP TABLE IF EXISTS x_coverage_checks;"
        "ALTER TABLE ai_models DROP COLUMN IF EXISTS price_web_search_per_k;"
    )
