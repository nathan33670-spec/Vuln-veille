"""Workflow engine (phase 3, step 3.1).

- ``workflow_versions`` are immutable: no role may update them;
- ``node_runs`` are unique per (run, node, attempt), the basis of idempotent execution;
- every table is private to its workspace (RLS). The dispatcher and the recovery
  sweep work across workspaces with the platform-admin context of the worker role;
  node tasks run with their workspace's context only.

Revision ID: 0008_workflows
Revises: 0007_vulnerabilities
Create Date: 2026-10-25 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0008_workflows"
down_revision: str | None = "0007_vulnerabilities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"
WORKER = f"workspace_id = ANY ({CTX_WORKSPACES}) OR {CTX_ADMIN}"
TABLES_WITH_RLS = (
    "workflows",
    "workflow_versions",
    "workflow_triggers",
    "workflow_runs",
    "node_runs",
    "workflow_approvals",
    "dedupe_keys",
)

TABLES = """
CREATE TABLE workflows (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'paused', 'archived')),
    active_version_id uuid,
    tags text[] NOT NULL DEFAULT '{}',
    seed_key text,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_workflows_name UNIQUE (workspace_id, name),
    CONSTRAINT uq_workflows_seed UNIQUE (workspace_id, seed_key)
);

CREATE TABLE workflow_versions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    workflow_id uuid NOT NULL REFERENCES workflows (id) ON DELETE CASCADE,
    version_no integer NOT NULL CHECK (version_no > 0),
    graph jsonb NOT NULL,
    graph_hash text NOT NULL,
    comment text NOT NULL DEFAULT '' CHECK (length(comment) <= 500),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_workflow_versions_no UNIQUE (workflow_id, version_no)
);
ALTER TABLE workflows ADD CONSTRAINT fk_workflows_active_version
    FOREIGN KEY (active_version_id) REFERENCES workflow_versions (id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE workflow_triggers (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    workflow_id uuid NOT NULL REFERENCES workflows (id) ON DELETE CASCADE,
    version_id uuid NOT NULL REFERENCES workflow_versions (id) ON DELETE CASCADE,
    node_id text NOT NULL,
    type text NOT NULL CHECK (type IN ('manual', 'schedule', 'event', 'webhook',
                                       'cve_published', 'cve_updated')),
    config jsonb NOT NULL DEFAULT '{}',
    next_fire_at timestamptz,
    webhook_secret_id uuid REFERENCES secrets (id),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_workflow_triggers_node UNIQUE (version_id, node_id)
);
CREATE INDEX ix_workflow_triggers_type ON workflow_triggers (type) WHERE enabled;
CREATE INDEX ix_workflow_triggers_schedule ON workflow_triggers (next_fire_at)
    WHERE enabled AND type = 'schedule';

CREATE TABLE workflow_runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    workflow_id uuid NOT NULL REFERENCES workflows (id) ON DELETE CASCADE,
    version_id uuid NOT NULL REFERENCES workflow_versions (id),
    trigger_type text NOT NULL,
    trigger_node_id text NOT NULL,
    triggered_by uuid REFERENCES users (id) ON DELETE SET NULL,
    trigger_payload jsonb NOT NULL DEFAULT '{}',
    idempotency_key text,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running',
        'waiting_approval', 'succeeded', 'failed', 'cancelled', 'timed_out')),
    cancel_requested boolean NOT NULL DEFAULT false,
    queued_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    deadline_at timestamptz,
    finished_at timestamptz,
    error text CHECK (length(error) <= 2000),
    stats jsonb NOT NULL DEFAULT '{}',
    CONSTRAINT uq_workflow_runs_idempotency UNIQUE (workflow_id, idempotency_key)
);
CREATE INDEX ix_workflow_runs_status ON workflow_runs (workspace_id, status);
CREATE INDEX ix_workflow_runs_workflow ON workflow_runs (workflow_id, queued_at DESC);

CREATE TABLE node_runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    run_id uuid NOT NULL REFERENCES workflow_runs (id) ON DELETE CASCADE,
    node_id text NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed',
        'skipped', 'waiting_approval', 'cancelled')),
    queue text NOT NULL,
    task_id text,
    scheduled_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    heartbeat_at timestamptz,
    finished_at timestamptz,
    input_count integer NOT NULL DEFAULT 0,
    output jsonb NOT NULL DEFAULT '{}',
    output_count integer NOT NULL DEFAULT 0,
    output_truncated boolean NOT NULL DEFAULT false,
    error text CHECK (length(error) <= 2000),
    logs jsonb NOT NULL DEFAULT '[]',
    metrics jsonb NOT NULL DEFAULT '{}',
    CONSTRAINT uq_node_runs_attempt UNIQUE (run_id, node_id, attempt)
);
CREATE INDEX ix_node_runs_run ON node_runs (run_id);
CREATE INDEX ix_node_runs_running ON node_runs (heartbeat_at) WHERE status = 'running';

CREATE TABLE workflow_approvals (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    run_id uuid NOT NULL REFERENCES workflow_runs (id) ON DELETE CASCADE,
    node_id text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    decided_by uuid REFERENCES users (id) ON DELETE SET NULL,
    decision text CHECK (decision IN ('approved', 'rejected')),
    comment text NOT NULL DEFAULT '' CHECK (length(comment) <= 2000),
    decided_at timestamptz,
    CONSTRAINT uq_workflow_approvals_node UNIQUE (run_id, node_id)
);

CREATE TABLE dedupe_keys (
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    namespace text NOT NULL CHECK (length(namespace) BETWEEN 1 AND 100),
    key_hash text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, namespace, key_hash)
);
CREATE INDEX ix_dedupe_keys_expiry ON dedupe_keys (expires_at);
"""

GRANTS = """
REVOKE UPDATE, TRUNCATE ON workflow_versions FROM vv_app, vv_worker;
REVOKE DELETE ON workflow_versions FROM vv_worker;
REVOKE INSERT, DELETE, TRUNCATE ON workflows FROM vv_worker;
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
        "ALTER TABLE workflows DROP CONSTRAINT IF EXISTS fk_workflows_active_version;"
        "DROP TABLE IF EXISTS dedupe_keys, workflow_approvals, node_runs, workflow_runs, "
        "workflow_triggers, workflow_versions, workflows;"
    )
