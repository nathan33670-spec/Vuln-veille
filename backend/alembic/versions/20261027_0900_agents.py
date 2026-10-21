"""AI agents: versioned configurations, runs and steps, monthly budgets (phase 4,
steps 4.7-4.11).

- ``ai_agents`` and their immutable ``ai_agent_versions`` are private to a workspace;
- ``agent_runs`` and ``agent_steps`` trace every execution (model served, tokens,
  estimated cost, tool calls, injection signals); steps are append-only;
- ``llm_budgets``: the monthly limit a workspace sets (API role only); ``llm_spend``:
  one row per workspace and calendar month, added to by the ``ai`` worker only. With a
  hard stop, engine calls are refused once the month's spend reaches the limit.

Revision ID: 0010_agents
Revises: 0009_ai_engines
Create Date: 2026-10-27 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0010_agents"
down_revision: str | None = "0009_ai_engines"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"
WORKER = f"workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN}"
TABLES_WITH_RLS = (
    "ai_agents",
    "ai_agent_versions",
    "agent_runs",
    "agent_steps",
    "llm_budgets",
    "llm_spend",
)

TABLES = """
CREATE TABLE ai_agents (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    active_version_id uuid,
    enabled boolean NOT NULL DEFAULT true,
    preset text,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_agents_name UNIQUE (workspace_id, name),
    CONSTRAINT uq_ai_agents_preset UNIQUE (workspace_id, preset)
);

CREATE TABLE ai_agent_versions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    agent_id uuid NOT NULL REFERENCES ai_agents (id) ON DELETE CASCADE,
    version_no integer NOT NULL CHECK (version_no > 0),
    spec jsonb NOT NULL,
    comment text NOT NULL DEFAULT '' CHECK (length(comment) <= 500),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_agent_versions_no UNIQUE (agent_id, version_no)
);
ALTER TABLE ai_agents ADD CONSTRAINT fk_ai_agents_active_version
    FOREIGN KEY (active_version_id) REFERENCES ai_agent_versions (id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE agent_runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    agent_id uuid NOT NULL REFERENCES ai_agents (id) ON DELETE CASCADE,
    agent_version_id uuid NOT NULL REFERENCES ai_agent_versions (id),
    context_type text NOT NULL
        CHECK (context_type IN ('node_run', 'vulnerability', 'test', 'evaluation')),
    context_id text,
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    input jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed',
        'refused', 'invalid_output', 'budget_exceeded', 'timed_out')),
    model_row_id uuid REFERENCES ai_models (id) ON DELETE SET NULL,
    engine_kind text,
    model_requested text,
    model_served text,
    stop_reason text,
    refusal_category text,
    turns integer NOT NULL DEFAULT 0,
    tool_calls integer NOT NULL DEFAULT 0,
    input_tokens integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    cache_read_tokens integer NOT NULL DEFAULT 0,
    cache_write_tokens integer NOT NULL DEFAULT 0,
    cost_estimate_usd numeric(12, 6) NOT NULL DEFAULT 0,
    output jsonb,
    sources jsonb NOT NULL DEFAULT '[]',
    injection_flags jsonb NOT NULL DEFAULT '[]',
    error text CHECK (length(error) <= 2000),
    queued_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX ix_agent_runs_agent ON agent_runs (agent_id, queued_at DESC);
CREATE INDEX ix_agent_runs_context ON agent_runs (context_type, context_id);

CREATE TABLE agent_steps (
    id bigserial PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    agent_run_id uuid NOT NULL REFERENCES agent_runs (id) ON DELETE CASCADE,
    seq integer NOT NULL,
    type text NOT NULL CHECK (type IN ('llm_call', 'tool_call', 'tool_result', 'validation')),
    payload jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_agent_steps_seq UNIQUE (agent_run_id, seq)
);

CREATE TABLE llm_budgets (
    workspace_id uuid PRIMARY KEY REFERENCES workspaces (id),
    monthly_limit_usd numeric(12, 2) CHECK (monthly_limit_usd >= 0),
    hard_stop boolean NOT NULL DEFAULT true,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE llm_spend (
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    period date NOT NULL CHECK (extract(day FROM period) = 1),
    spent_usd numeric(12, 6) NOT NULL DEFAULT 0 CHECK (spent_usd >= 0),
    input_tokens bigint NOT NULL DEFAULT 0,
    output_tokens bigint NOT NULL DEFAULT 0,
    calls integer NOT NULL DEFAULT 0,
    alerts_sent integer[] NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, period)
);
"""

GRANTS = """
REVOKE UPDATE, TRUNCATE ON ai_agent_versions FROM vv_app, vv_worker;
REVOKE DELETE ON ai_agent_versions FROM vv_worker;
REVOKE UPDATE, DELETE, TRUNCATE ON agent_steps FROM vv_app, vv_worker;
REVOKE INSERT, DELETE, TRUNCATE ON ai_agents FROM vv_worker;
REVOKE DELETE, TRUNCATE ON agent_runs, llm_spend FROM vv_worker;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON llm_budgets FROM vv_worker;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON llm_spend FROM vv_app;
"""


def _policies() -> str:
    return "\n".join(
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {t}_app ON {t} TO vv_app USING ({APP}) WITH CHECK ({APP});\n"
        f"CREATE POLICY {t}_worker ON {t} TO vv_worker USING ({WORKER}) WITH CHECK ({WORKER});"
        for t in TABLES_WITH_RLS
    )


def upgrade() -> None:
    for script in (TABLES, GRANTS, _policies()):
        execute_script(script)


def downgrade() -> None:
    execute_script(
        "ALTER TABLE ai_agents DROP CONSTRAINT IF EXISTS fk_ai_agents_active_version;"
        "DROP TABLE IF EXISTS llm_spend, llm_budgets, agent_steps, agent_runs, ai_agent_versions, ai_agents;"
    )
