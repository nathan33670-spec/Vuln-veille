"""Publications: pushes of a bulletin to a connector, their attempts, and what each
target holds (phase 7, merge request 7B, spec 05 §4).

- ``publication_targets``: per bulletin and connector, the remote identifier (create
  then update), the first push (its author: the second factor is asked only then,
  Q43) and the last revision sent;
- ``publications``: one push (from a person, a workflow or a connection test), its
  status, retries and outcome;
- ``publication_attempts``: every HTTP attempt, redacted request, status, excerpt of
  the response (4 KiB at most), error and duration.

Written by the ``publish`` worker; the API creates queued pushes and reads.

Revision ID: 0018_publications
Revises: 0017_publish_connectors
Create Date: 2026-11-04 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0018_publications"
down_revision: str | None = "0017_publish_connectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
MEMBER = f"workspace_id = ANY ({CTX_WORKSPACES})"
TABLES = ("publication_targets", "publications", "publication_attempts")

UPGRADE = """
CREATE TABLE publication_targets (
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    bulletin_id uuid NOT NULL REFERENCES bulletins (id) ON DELETE CASCADE,
    connector_id uuid NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    remote_id text CHECK (length(remote_id) <= 500),
    first_pushed_at timestamptz,
    first_pushed_by uuid REFERENCES users (id) ON DELETE SET NULL,
    last_rev_no integer,
    last_status text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bulletin_id, connector_id)
);

CREATE TABLE publications (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    bulletin_id uuid REFERENCES bulletins (id) ON DELETE CASCADE,
    connector_id uuid NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    connector_version integer NOT NULL,
    revision_id uuid REFERENCES bulletin_revisions (id),
    rev_no integer,
    is_test boolean NOT NULL DEFAULT false,
    origin text NOT NULL CHECK (origin IN ('user', 'workflow', 'test')),
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    node_run_id uuid,
    status text NOT NULL CHECK (status IN (
        'queued', 'sending', 'retrying', 'succeeded', 'failed')),
    mode text CHECK (mode IN ('create', 'update')),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    idempotency_key text,
    remote_id text CHECK (length(remote_id) <= 500),
    response_status integer,
    error text CHECK (length(error) <= 500),
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    CHECK (is_test OR bulletin_id IS NOT NULL)
);
CREATE INDEX ix_publications_bulletin ON publications (bulletin_id, created_at DESC);
CREATE INDEX ix_publications_connector ON publications (connector_id, created_at DESC);
CREATE INDEX ix_publications_open ON publications (workspace_id)
    WHERE status IN ('queued', 'sending', 'retrying');

CREATE TABLE publication_attempts (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    publication_id uuid NOT NULL REFERENCES publications (id) ON DELETE CASCADE,
    attempt_no integer NOT NULL CHECK (attempt_no >= 1),
    request jsonb NOT NULL,
    response_status integer,
    response_excerpt text CHECK (length(response_excerpt) <= 4096),
    error text CHECK (length(error) <= 500),
    duration_ms integer,
    started_at timestamptz NOT NULL,
    UNIQUE (publication_id, attempt_no)
);

REVOKE DELETE, TRUNCATE ON publication_targets, publications, publication_attempts
    FROM vv_app, vv_worker;
REVOKE INSERT, UPDATE ON publication_attempts FROM vv_app;
REVOKE UPDATE ON publication_attempts FROM vv_worker;
"""


def _policies() -> str:
    return "\n".join(
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {t}_app ON {t} TO vv_app USING ({MEMBER}) WITH CHECK ({MEMBER});\n"
        f"CREATE POLICY {t}_worker ON {t} TO vv_worker USING ({MEMBER}) WITH CHECK ({MEMBER});"
        for t in TABLES
    )


def upgrade() -> None:
    execute_script(UPGRADE)
    execute_script(_policies())


def downgrade() -> None:
    execute_script("DROP TABLE IF EXISTS publication_attempts, publications, publication_targets;")
