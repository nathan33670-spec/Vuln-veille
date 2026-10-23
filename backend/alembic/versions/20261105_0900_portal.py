"""Client portal: what clients see of published bulletins (phase 8, 8A, spec 06, ADR-031).

- ``bulletin_publication_events``: a snapshot taken at each publication, update and
  withdrawal: the published revision, its title, severity, TLP, audience, CVEs and
  technologies as they were approved. An update in progress changes the bulletin's
  own columns (title, TLP, audience) before anyone approves it: the portal never reads
  them, only the latest snapshot.
- ``portal_bulletins_v`` and ``portal_bulletin_history_v``: security-barrier views
  owned by the migration role, the only bulletin data ``vv_portal`` may read. They
  filter on the request's organisation (``app.client_org_id``) and on the TLP rules
  (Q22): CLEAR and GREEN for every client, or the organisations chosen; AMBER only
  for organisations explicitly chosen; RED never.
- existing published bulletins get their first snapshot from their current state.

Revision ID: 0019_portal
Revises: 0018_publications
Create Date: 2026-11-05 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0019_portal"
down_revision: str | None = "0018_publications"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
CTX_ORG = "nullif(current_setting('app.client_org_id', true), '')::uuid"
MEMBER = f"workspace_id = ANY ({CTX_WORKSPACES})"

UPGRADE = f"""
CREATE TABLE bulletin_publication_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    bulletin_id uuid NOT NULL REFERENCES bulletins (id) ON DELETE CASCADE,
    revision_id uuid REFERENCES bulletin_revisions (id),
    rev_no integer,
    kind text NOT NULL CHECK (kind IN ('published', 'updated', 'withdrawn')),
    at timestamptz NOT NULL,
    ref text NOT NULL,
    language text NOT NULL,
    team text NOT NULL,
    title text NOT NULL CHECK (length(title) <= 300),
    severity text,
    tlp text NOT NULL CHECK (tlp IN ('CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED')),
    audience_type text NOT NULL CHECK (audience_type IN ('all_clients', 'selected')),
    audience_org_ids uuid[] NOT NULL DEFAULT '{{}}',
    cves text[] NOT NULL DEFAULT '{{}}',
    technologies jsonb NOT NULL DEFAULT '[]',
    notified_at timestamptz
);
CREATE INDEX ix_bulletin_publication_events_bulletin
    ON bulletin_publication_events (bulletin_id, at DESC);

REVOKE UPDATE, DELETE, TRUNCATE ON bulletin_publication_events FROM vv_app;
REVOKE DELETE, TRUNCATE ON bulletin_publication_events FROM vv_worker;
ALTER TABLE bulletin_publication_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY bulletin_publication_events_app ON bulletin_publication_events TO vv_app
    USING ({MEMBER}) WITH CHECK ({MEMBER});
CREATE POLICY bulletin_publication_events_worker ON bulletin_publication_events TO vv_worker
    USING ({MEMBER}) WITH CHECK ({MEMBER});

-- Existing published bulletins: a first snapshot from their current state.
INSERT INTO bulletin_publication_events (
    id, workspace_id, bulletin_id, revision_id, rev_no, kind, at, ref, language, team,
    title, severity, tlp, audience_type, audience_org_ids, cves, technologies)
SELECT gen_random_uuid(), b.workspace_id, b.id, r.id, r.rev_no, 'published',
       coalesce(b.published_at, now()), b.ref, b.language, upper(w.slug),
       coalesce(r.fields ->> 'title', b.title), r.fields ->> 'severity', b.tlp,
       b.audience_type,
       coalesce((SELECT array_agg(a.client_org_id) FROM bulletin_audiences a
                 WHERE a.bulletin_id = b.id), '{{}}'),
       coalesce((SELECT array_agg(v.cve_id ORDER BY v.cve_id) FROM bulletin_vulnerabilities bv
                 JOIN vulnerabilities v ON v.id = bv.vulnerability_id
                 WHERE bv.bulletin_id = b.id AND v.cve_id IS NOT NULL), '{{}}'),
       coalesce((SELECT jsonb_agg(jsonb_build_object(
                     'vendor', t.vendor, 'product', t.product, 'name', t.display_name))
                 FROM bulletin_technologies bt JOIN technologies t ON t.id = bt.technology_id
                 WHERE bt.bulletin_id = b.id), '[]')
FROM bulletins b
JOIN bulletin_revisions r ON r.id = b.published_revision_id
JOIN workspaces w ON w.id = b.workspace_id
WHERE b.status <> 'withdrawn';

-- The latest snapshot of each bulletin, when it is a publication or an update.
CREATE VIEW portal_published_v WITH (security_barrier = true) AS
SELECT DISTINCT ON (e.bulletin_id) e.*
FROM bulletin_publication_events e
ORDER BY e.bulletin_id, e.at DESC, e.id DESC;

CREATE VIEW portal_bulletins_v WITH (security_barrier = true) AS
SELECT p.bulletin_id AS id, p.ref, p.language, p.team, p.title, p.severity, p.tlp,
       p.rev_no, p.cves, p.technologies,
       (SELECT min(f.at) FROM bulletin_publication_events f
        WHERE f.bulletin_id = p.bulletin_id AND f.kind = 'published') AS published_at,
       p.at AS updated_at,
       r.rendered_html AS html, r.rendered_markdown AS markdown
FROM portal_published_v p
JOIN bulletin_revisions r ON r.id = p.revision_id
WHERE p.kind IN ('published', 'updated')
  AND {CTX_ORG} IS NOT NULL
  AND EXISTS (SELECT 1 FROM client_organizations o
              WHERE o.id = {CTX_ORG} AND o.status = 'active')
  AND (
    (p.tlp IN ('CLEAR', 'GREEN')
     AND (p.audience_type = 'all_clients' OR {CTX_ORG} = ANY (p.audience_org_ids)))
    OR (p.tlp IN ('AMBER', 'AMBER+STRICT')
        AND p.audience_type = 'selected' AND {CTX_ORG} = ANY (p.audience_org_ids))
  );

CREATE VIEW portal_bulletin_history_v WITH (security_barrier = true) AS
SELECT e.bulletin_id, e.rev_no, e.kind, e.at
FROM bulletin_publication_events e
WHERE e.kind IN ('published', 'updated')
  AND e.bulletin_id IN (SELECT id FROM portal_bulletins_v);

-- The views read with their owner's rights (no RLS): only the portal role uses them;
-- the default privileges of vv_app and vv_worker are taken back.
REVOKE ALL ON portal_published_v, portal_bulletins_v, portal_bulletin_history_v
    FROM PUBLIC, vv_app, vv_worker;
GRANT SELECT ON portal_bulletins_v, portal_bulletin_history_v TO vv_portal;
"""

DOWNGRADE = """
DROP VIEW IF EXISTS portal_bulletin_history_v;
DROP VIEW IF EXISTS portal_bulletins_v;
DROP VIEW IF EXISTS portal_published_v;
DROP TABLE IF EXISTS bulletin_publication_events;
"""


def upgrade() -> None:
    execute_script(UPGRADE)


def downgrade() -> None:
    execute_script(DOWNGRADE)
