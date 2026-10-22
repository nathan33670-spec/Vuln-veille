"""Bulletin templates (phase 6, steps 6.1 to 6.3, spec 04 §1-2).

- ``bulletin_settings``: per workspace, the reference prefix of its bulletins
  (``CERT-AVI-2026-0007``), the optional double validation (off by default, Q4) and the
  default template used when no rule matches;
- ``bulletin_templates`` and their immutable ``bulletin_template_versions``: fields,
  per-field AI instructions, Liquid render template, style guide, example, language,
  default TLP and matching rules, stored as one validated ``spec`` document.

Workspace data (RLS); the worker reads them to generate drafts.

Revision ID: 0015_bulletin_templates
Revises: 0014_editor
Create Date: 2026-11-01 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0015_bulletin_templates"
down_revision: str | None = "0014_editor"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
APP = f"workspace_id = ANY ({CTX_WORKSPACES})"

TABLES = """
CREATE TABLE bulletin_templates (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived')),
    active_version_id uuid,
    seed_key text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1,
    UNIQUE (workspace_id, name),
    UNIQUE (workspace_id, seed_key)
);

CREATE TABLE bulletin_template_versions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    template_id uuid NOT NULL REFERENCES bulletin_templates (id) ON DELETE CASCADE,
    version_no integer NOT NULL CHECK (version_no >= 1),
    spec jsonb NOT NULL,
    language text NOT NULL CHECK (language IN ('fr', 'en')),
    priority integer NOT NULL,
    comment text NOT NULL DEFAULT '' CHECK (length(comment) <= 500),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (template_id, version_no)
);
ALTER TABLE bulletin_templates ADD CONSTRAINT fk_bulletin_templates_active
    FOREIGN KEY (active_version_id) REFERENCES bulletin_template_versions (id);

CREATE TABLE bulletin_settings (
    workspace_id uuid PRIMARY KEY REFERENCES workspaces (id),
    ref_prefix text NOT NULL CHECK (ref_prefix ~ '^[A-Z][A-Z0-9-]{0,15}$'),
    review_required boolean NOT NULL DEFAULT false,
    default_template_id uuid REFERENCES bulletin_templates (id) ON DELETE SET NULL,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1
);
"""

GRANTS = """
REVOKE UPDATE, TRUNCATE ON bulletin_template_versions FROM vv_app, vv_worker;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
    ON bulletin_templates, bulletin_template_versions, bulletin_settings FROM vv_worker;
"""


def _policies() -> str:
    return "\n".join(
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {t}_app ON {t} TO vv_app USING ({APP}) WITH CHECK ({APP});\n"
        f"CREATE POLICY {t}_worker ON {t} FOR SELECT TO vv_worker USING ({APP});"
        for t in ("bulletin_templates", "bulletin_template_versions", "bulletin_settings")
    )


def upgrade() -> None:
    for script in (TABLES, GRANTS, _policies()):
        execute_script(script)


def downgrade() -> None:
    execute_script(
        """
DROP TABLE IF EXISTS bulletin_settings;
ALTER TABLE bulletin_templates DROP CONSTRAINT fk_bulletin_templates_active;
DROP TABLE IF EXISTS bulletin_template_versions;
DROP TABLE IF EXISTS bulletin_templates;
"""
    )
