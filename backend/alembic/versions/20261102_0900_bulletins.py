"""Bulletins, revisions and draft requests (phase 6, steps 6.4 to 6.8, spec 04 §3-5).

- ``draft_requests``: an analyst's (or a workflow's) request for a draft, a regenerated
  field or a translation, executed by the ``ai`` worker, with its progress;
- ``bulletins``: reference (workspace prefix, year, counter), language, translation
  link, status, TLP, audience, template version, current and published revisions;
- ``bulletin_revisions``: immutable field values and their sanitised rendering;
- links to vulnerabilities, technologies and client organisations.

A bulletin stays visible to clients through its published revision while an update
goes through review (``published_revision_id`` set, status back to ``draft``…). A
published revision is readable by the other team (ADR-024); the rest is workspace data.

Revision ID: 0016_bulletins
Revises: 0015_bulletin_templates
Create Date: 2026-11-02 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0016_bulletins"
down_revision: str | None = "0015_bulletin_templates"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"

TABLES = """
CREATE TABLE bulletin_ref_counters (
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    year integer NOT NULL,
    last_no integer NOT NULL,
    PRIMARY KEY (workspace_id, year)
);

CREATE TABLE bulletins (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    ref text NOT NULL CHECK (length(ref) <= 40),
    language text NOT NULL CHECK (language IN ('fr', 'en')),
    translation_of uuid REFERENCES bulletins (id),
    title text NOT NULL CHECK (length(title) <= 300),
    status text NOT NULL CHECK (status IN (
        'draft', 'in_review', 'approved', 'published', 'withdrawn')),
    severity text CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    tlp text NOT NULL CHECK (tlp IN ('CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED')),
    audience_type text NOT NULL DEFAULT 'all_clients'
        CHECK (audience_type IN ('all_clients', 'selected')),
    template_version_id uuid NOT NULL REFERENCES bulletin_template_versions (id),
    current_revision_id uuid,
    published_revision_id uuid,
    author_id uuid REFERENCES users (id) ON DELETE SET NULL,
    submitted_by uuid REFERENCES users (id) ON DELETE SET NULL,
    reviewer_id uuid REFERENCES users (id) ON DELETE SET NULL,
    approved_at timestamptz,
    published_at timestamptz,
    published_by uuid REFERENCES users (id) ON DELETE SET NULL,
    withdrawn_at timestamptz,
    withdrawn_reason text CHECK (length(withdrawn_reason) <= 1000),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1,
    UNIQUE (workspace_id, ref)
);
CREATE INDEX ix_bulletins_published ON bulletins (published_at DESC)
    WHERE published_revision_id IS NOT NULL;

CREATE TABLE bulletin_revisions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    bulletin_id uuid NOT NULL REFERENCES bulletins (id) ON DELETE CASCADE,
    rev_no integer NOT NULL CHECK (rev_no >= 1),
    fields jsonb NOT NULL,
    rendered_markdown text NOT NULL,
    rendered_html text NOT NULL,
    content_hash text NOT NULL,
    created_by_type text NOT NULL CHECK (created_by_type IN ('ai', 'user')),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    agent_run_id uuid,
    change_note text NOT NULL DEFAULT '' CHECK (length(change_note) <= 500),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (bulletin_id, rev_no)
);
ALTER TABLE bulletins ADD CONSTRAINT fk_bulletins_current
    FOREIGN KEY (current_revision_id) REFERENCES bulletin_revisions (id);
ALTER TABLE bulletins ADD CONSTRAINT fk_bulletins_published
    FOREIGN KEY (published_revision_id) REFERENCES bulletin_revisions (id);

CREATE TABLE bulletin_vulnerabilities (
    bulletin_id uuid NOT NULL REFERENCES bulletins (id) ON DELETE CASCADE,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    PRIMARY KEY (bulletin_id, vulnerability_id)
);
CREATE TABLE bulletin_technologies (
    bulletin_id uuid NOT NULL REFERENCES bulletins (id) ON DELETE CASCADE,
    technology_id uuid NOT NULL REFERENCES technologies (id),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    PRIMARY KEY (bulletin_id, technology_id)
);
CREATE TABLE bulletin_audiences (
    bulletin_id uuid NOT NULL REFERENCES bulletins (id) ON DELETE CASCADE,
    client_org_id uuid NOT NULL REFERENCES client_organizations (id) ON DELETE CASCADE,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    PRIMARY KEY (bulletin_id, client_org_id)
);

CREATE TABLE draft_requests (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    kind text NOT NULL CHECK (kind IN ('draft', 'field', 'translation')),
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    input jsonb NOT NULL,
    template_version_id uuid REFERENCES bulletin_template_versions (id),
    extra_instructions text NOT NULL DEFAULT '' CHECK (length(extra_instructions) <= 2000),
    status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    progress jsonb NOT NULL DEFAULT '[]',
    bulletin_id uuid REFERENCES bulletins (id) ON DELETE SET NULL,
    agent_run_id uuid,
    error text CHECK (length(error) <= 2000),
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX ix_draft_requests_recent ON draft_requests (workspace_id, created_at DESC);

ALTER TABLE agent_runs DROP CONSTRAINT agent_runs_context_type_check;
ALTER TABLE agent_runs ADD CONSTRAINT agent_runs_context_type_check CHECK (context_type IN (
    'node_run', 'vulnerability', 'test', 'evaluation', 'draft_request'));
"""

GRANTS = """
REVOKE UPDATE, DELETE, TRUNCATE ON bulletin_revisions FROM vv_app, vv_worker;
REVOKE DELETE, TRUNCATE ON bulletins, bulletin_ref_counters, draft_requests FROM vv_worker;
"""

WORKSPACE_TABLES = (
    "bulletin_ref_counters",
    "bulletin_vulnerabilities",
    "bulletin_technologies",
    "bulletin_audiences",
    "draft_requests",
)
# The other team reads published bulletins and their published revision (ADR-024).
PUBLISHED = "published_revision_id IS NOT NULL AND status <> 'withdrawn'"
PUBLISHED_REVISION = (
    "EXISTS (SELECT 1 FROM bulletins b WHERE b.id = bulletin_id "
    "AND b.published_revision_id = bulletin_revisions.id AND b.status <> 'withdrawn')"
)


def _policies() -> str:
    lines = [
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {t}_app ON {t} TO vv_app USING ({APP}) WITH CHECK ({APP});\n"
        f"CREATE POLICY {t}_worker ON {t} TO vv_worker USING ({APP}) WITH CHECK ({APP});"
        for t in (*WORKSPACE_TABLES, "bulletins", "bulletin_revisions")
    ]
    lines += [
        f"CREATE POLICY bulletins_published ON bulletins FOR SELECT TO vv_app USING ({PUBLISHED});",
        "CREATE POLICY bulletin_revisions_published ON bulletin_revisions FOR SELECT TO vv_app "
        f"USING ({PUBLISHED_REVISION});",
    ]
    return "\n".join(lines)


def upgrade() -> None:
    for script in (TABLES, GRANTS, _policies()):
        execute_script(script)


def downgrade() -> None:
    execute_script(
        """
DELETE FROM agent_runs WHERE context_type = 'draft_request';
ALTER TABLE agent_runs DROP CONSTRAINT agent_runs_context_type_check;
ALTER TABLE agent_runs ADD CONSTRAINT agent_runs_context_type_check CHECK (context_type IN (
    'node_run', 'vulnerability', 'test', 'evaluation'));
DROP TABLE IF EXISTS draft_requests;
DROP TABLE IF EXISTS bulletin_audiences;
DROP TABLE IF EXISTS bulletin_technologies;
DROP TABLE IF EXISTS bulletin_vulnerabilities;
ALTER TABLE bulletins DROP CONSTRAINT fk_bulletins_current;
ALTER TABLE bulletins DROP CONSTRAINT fk_bulletins_published;
DROP TABLE IF EXISTS bulletin_revisions;
DROP TABLE IF EXISTS bulletins;
DROP TABLE IF EXISTS bulletin_ref_counters;
"""
    )
