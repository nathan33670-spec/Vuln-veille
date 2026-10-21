"""Vulnerabilities shared by VOC and CERT, qualified per team (steps 2.10-2.11, ADR-024).

- ``vulnerabilities``, ``vulnerability_technologies``, ``vulnerability_evidence``,
  ``vulnerability_analyses`` and ``vulnerability_events`` are internal and global:
  every internal user reads them; the portal role has no grant at all.
- ``vulnerability_assessments`` are per team: readable by every internal user (the
  other team sees "qualified by CERT" and can adopt it) but written only by their own
  workspace.
- ``vulnerability_comments`` stay private to their team.
- Vulnerabilities are never deleted (``duplicate_of`` instead); the timeline is
  append-only. Collected items cited as evidence become readable by both teams.

Revision ID: 0007_vulnerabilities
Revises: 0006_watch
Create Date: 2026-10-24 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0007_vulnerabilities"
down_revision: str | None = "0006_watch"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
IN_WORKSPACE = f"workspace_id = ANY ({CTX_WORKSPACES})"

TABLES = """
CREATE SEQUENCE vulnerability_ref_seq;

CREATE TABLE vulnerabilities (
    id uuid PRIMARY KEY,
    ref text NOT NULL UNIQUE DEFAULT (
        'VV-' || to_char(now() AT TIME ZONE 'UTC', 'YYYY') || '-'
        || lpad(nextval('vulnerability_ref_seq')::text, 4, '0')
    ),
    cve_id text UNIQUE CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    aliases text[] NOT NULL DEFAULT '{}',
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    summary text NOT NULL DEFAULT '' CHECK (length(summary) <= 20000),
    duplicate_of uuid REFERENCES vulnerabilities (id),
    exploitation_status text NOT NULL DEFAULT 'unknown'
        CHECK (exploitation_status IN ('unknown', 'poc_public', 'exploited_itw', 'not_exploitable')),
    patch_status text NOT NULL DEFAULT 'unknown'
        CHECK (patch_status IN ('unknown', 'available', 'partial', 'none', 'workaround')),
    first_seen_at timestamptz NOT NULL,
    origin text NOT NULL CHECK (origin IN ('workflow', 'user')),
    origin_workspace_id uuid REFERENCES workspaces (id),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_vulnerabilities_not_self_duplicate CHECK (duplicate_of <> id)
);
CREATE INDEX ix_vulnerabilities_aliases ON vulnerabilities USING gin (aliases);
CREATE INDEX ix_vulnerabilities_title_trgm ON vulnerabilities USING gin (title gin_trgm_ops);

CREATE TABLE vulnerability_assessments (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    status text NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'triage', 'qualified', 'rejected', 'duplicate', 'monitoring')),
    priority text CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    severity text CHECK (severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cvss_override jsonb,
    assignee_id uuid REFERENCES users (id) ON DELETE SET NULL,
    rationale text NOT NULL DEFAULT '' CHECK (length(rationale) <= 20000),
    qualified_at timestamptz,
    qualified_by uuid REFERENCES users (id) ON DELETE SET NULL,
    copied_from_assessment_id uuid REFERENCES vulnerability_assessments (id) ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_assessments_team UNIQUE (vulnerability_id, workspace_id),
    CONSTRAINT ck_assessments_qualified CHECK (status <> 'qualified' OR priority IS NOT NULL)
);
CREATE INDEX ix_assessments_workspace_status ON vulnerability_assessments (workspace_id, status);

CREATE TABLE vulnerability_technologies (
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    technology_id uuid NOT NULL REFERENCES technologies (id),
    matched_by text NOT NULL CHECK (matched_by IN ('cpe', 'purl', 'ai', 'manual')),
    confidence numeric(3, 2) NOT NULL DEFAULT 1 CHECK (confidence BETWEEN 0 AND 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vulnerability_id, technology_id)
);

CREATE TABLE vulnerability_evidence (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    collected_item_id uuid NOT NULL REFERENCES collected_items (id),
    kind text NOT NULL
        CHECK (kind IN ('advisory', 'poc', 'exploit', 'patch', 'discussion', 'mention', 'news')),
    note text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    confidence numeric(3, 2) NOT NULL DEFAULT 1 CHECK (confidence BETWEEN 0 AND 1),
    added_by_type text NOT NULL CHECK (added_by_type IN ('user', 'agent', 'workflow')),
    added_by uuid REFERENCES users (id) ON DELETE SET NULL,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_evidence_item UNIQUE (vulnerability_id, collected_item_id)
);

CREATE TABLE vulnerability_analyses (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    agent_run_id uuid,
    content jsonb NOT NULL,
    injection_flags jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_analyses_vulnerability ON vulnerability_analyses (vulnerability_id, created_at DESC);

CREATE TABLE vulnerability_comments (
    id uuid PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    author_id uuid REFERENCES users (id) ON DELETE SET NULL,
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 20000),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_comments_vulnerability ON vulnerability_comments (vulnerability_id, workspace_id);

CREATE TABLE vulnerability_events (
    id bigserial PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities (id),
    workspace_id uuid REFERENCES workspaces (id),
    type text NOT NULL CHECK (type ~ '^[a-z_]+(\\.[a-z_]+)*$'),
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'system', 'agent', 'workflow')),
    actor_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    data jsonb NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_vulnerability_events ON vulnerability_events (vulnerability_id, occurred_at);
"""

GRANTS = """
REVOKE DELETE, TRUNCATE ON vulnerabilities FROM vv_app, vv_worker;
REVOKE UPDATE, DELETE, TRUNCATE ON vulnerability_events FROM vv_app, vv_worker;
REVOKE UPDATE, DELETE, TRUNCATE ON vulnerability_analyses FROM vv_app, vv_worker;
"""

POLICIES = f"""
ALTER TABLE vulnerability_assessments ENABLE ROW LEVEL SECURITY;
CREATE POLICY assessments_read ON vulnerability_assessments FOR SELECT TO vv_app, vv_worker
    USING (true);
CREATE POLICY assessments_insert ON vulnerability_assessments FOR INSERT TO vv_app, vv_worker
    WITH CHECK ({IN_WORKSPACE});
CREATE POLICY assessments_update ON vulnerability_assessments FOR UPDATE TO vv_app, vv_worker
    USING ({IN_WORKSPACE}) WITH CHECK ({IN_WORKSPACE});
CREATE POLICY assessments_delete ON vulnerability_assessments FOR DELETE TO vv_app, vv_worker
    USING ({IN_WORKSPACE});

ALTER TABLE vulnerability_comments ENABLE ROW LEVEL SECURITY;
CREATE POLICY comments_team ON vulnerability_comments TO vv_app, vv_worker
    USING ({IN_WORKSPACE}) WITH CHECK ({IN_WORKSPACE});

-- Evidence and analyses are shared, but each team only adds its own.
ALTER TABLE vulnerability_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY evidence_read ON vulnerability_evidence FOR SELECT TO vv_app, vv_worker USING (true);
CREATE POLICY evidence_write ON vulnerability_evidence FOR INSERT TO vv_app, vv_worker
    WITH CHECK ({IN_WORKSPACE});
CREATE POLICY evidence_delete ON vulnerability_evidence FOR DELETE TO vv_app, vv_worker
    USING ({IN_WORKSPACE});
ALTER TABLE vulnerability_analyses ENABLE ROW LEVEL SECURITY;
CREATE POLICY analyses_read ON vulnerability_analyses FOR SELECT TO vv_app, vv_worker USING (true);
CREATE POLICY analyses_write ON vulnerability_analyses FOR INSERT TO vv_app, vv_worker
    WITH CHECK ({IN_WORKSPACE});

-- An item cited as evidence is readable by both teams (ADR-024).
CREATE POLICY collected_items_evidence ON collected_items FOR SELECT TO vv_app, vv_worker
    USING (id IN (SELECT collected_item_id FROM vulnerability_evidence));
"""


def upgrade() -> None:
    for script in (TABLES, GRANTS, POLICIES):
        execute_script(script)


def downgrade() -> None:
    execute_script(
        """
        DROP POLICY IF EXISTS collected_items_evidence ON collected_items;
        DROP TABLE IF EXISTS vulnerability_events, vulnerability_comments, vulnerability_analyses,
            vulnerability_evidence, vulnerability_technologies, vulnerability_assessments,
            vulnerabilities;
        DROP SEQUENCE IF EXISTS vulnerability_ref_seq;
        """
    )
