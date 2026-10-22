"""Engine evaluation bench (phase 4, step 4.16).

- ``ai_eval_cases``: the reference CVEs of a workspace, with the expected key fields
  validated by its analysts;
- ``ai_eval_runs``: one agent version played on the cases with a candidate model,
  budgeted, with per-case results and the aggregated metrics. Comparing two runs
  gives the report kept with an engine switch decision.

Revision ID: 0012_ai_evaluation
Revises: 0011_ai_tasks
Create Date: 2026-10-29 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0012_ai_evaluation"
down_revision: str | None = "0011_ai_tasks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"
WORKER = f"workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN}"

TABLES = """
CREATE TABLE ai_eval_cases (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    input jsonb NOT NULL DEFAULT '{}',
    expected jsonb NOT NULL DEFAULT '{}',
    notes text NOT NULL DEFAULT '' CHECK (length(notes) <= 2000),
    validated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_eval_cases_cve UNIQUE (workspace_id, cve_id)
);

CREATE TABLE ai_eval_runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    agent_id uuid NOT NULL REFERENCES ai_agents (id) ON DELETE CASCADE,
    agent_version_id uuid NOT NULL REFERENCES ai_agent_versions (id),
    model_row_id uuid NOT NULL REFERENCES ai_models (id) ON DELETE CASCADE,
    model_id text NOT NULL,
    status text NOT NULL
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'budget_exceeded')),
    max_cost_usd numeric(10, 4) NOT NULL CHECK (max_cost_usd >= 0),
    case_ids uuid[] NOT NULL,
    results jsonb NOT NULL DEFAULT '[]',
    metrics jsonb NOT NULL DEFAULT '{}',
    error text CHECK (length(error) <= 500),
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    queued_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX ix_ai_eval_runs_workspace ON ai_eval_runs (workspace_id, queued_at DESC);
"""

GRANTS = """
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ai_eval_cases FROM vv_worker;
REVOKE INSERT, DELETE, TRUNCATE ON ai_eval_runs FROM vv_worker;
REVOKE UPDATE, DELETE, TRUNCATE ON ai_eval_runs FROM vv_app;
"""


def _policies() -> str:
    return "\n".join(
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {t}_app ON {t} TO vv_app USING ({APP}) WITH CHECK ({APP});\n"
        f"CREATE POLICY {t}_worker ON {t} TO vv_worker USING ({WORKER}) WITH CHECK ({WORKER});"
        for t in ("ai_eval_cases", "ai_eval_runs")
    )


def upgrade() -> None:
    for script in (TABLES, GRANTS, _policies()):
        execute_script(script)


def downgrade() -> None:
    execute_script("DROP TABLE IF EXISTS ai_eval_runs, ai_eval_cases;")
