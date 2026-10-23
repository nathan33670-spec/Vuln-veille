"""Publication connectors (phase 7, merge request 7A, spec 05, ADR-030).

- ``bulletin_settings``: the CSAF publisher of each workspace (Q42);
- ``private_network_requests``: a connector's request to reach a private range, and
  the platform administrator's decision (Q41). Administrators see every request
  (name, URL hosts, ranges, requester) without seeing the other team's connectors;
  the workers apply a range only while an approved request matches the connector's
  current hosts and ranges. The approval columns of ``connectors`` (never written by
  any route) are dropped: the decision lives in the request only;
- members of a workspace read the global publication connectors (Q40), whose secrets
  may be global (purpose ``connector``).

Revision ID: 0017_publish_connectors
Revises: 0016_bulletins
Create Date: 2026-11-03 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0017_publish_connectors"
down_revision: str | None = "0016_bulletins"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"
CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
MEMBER = f"workspace_id = ANY ({CTX_WORKSPACES})"

UPGRADE = f"""
ALTER TABLE bulletin_settings
    ADD COLUMN csaf_publisher_name text NOT NULL DEFAULT ''
        CHECK (length(csaf_publisher_name) <= 200),
    ADD COLUMN csaf_publisher_namespace text NOT NULL DEFAULT ''
        CHECK (csaf_publisher_namespace = '' OR csaf_publisher_namespace ~ '^https://'),
    ADD COLUMN csaf_publisher_category text NOT NULL DEFAULT 'coordinator'
        CHECK (csaf_publisher_category IN (
            'coordinator', 'discoverer', 'other', 'translator', 'user', 'vendor'));

CREATE TABLE private_network_requests (
    id uuid PRIMARY KEY,
    connector_id uuid NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    workspace_id uuid REFERENCES workspaces (id),
    connector_name text NOT NULL,
    hosts text[] NOT NULL CHECK (cardinality(hosts) BETWEEN 1 AND 5),
    cidrs cidr[] NOT NULL CHECK (cardinality(cidrs) BETWEEN 1 AND 10),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    status text NOT NULL CHECK (status IN (
        'pending', 'approved', 'rejected', 'superseded', 'revoked')),
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    decided_by uuid REFERENCES users (id) ON DELETE SET NULL,
    decided_at timestamptz,
    decision_note text NOT NULL DEFAULT '' CHECK (length(decision_note) <= 1000)
);
CREATE INDEX ix_private_network_requests_connector
    ON private_network_requests (connector_id, requested_at DESC);
CREATE INDEX ix_private_network_requests_pending
    ON private_network_requests (requested_at) WHERE status = 'pending';

REVOKE DELETE, TRUNCATE ON private_network_requests FROM vv_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON private_network_requests FROM vv_worker;

ALTER TABLE private_network_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY private_network_requests_read ON private_network_requests FOR SELECT TO vv_app
    USING ({MEMBER} OR {CTX_ADMIN});
CREATE POLICY private_network_requests_insert ON private_network_requests FOR INSERT TO vv_app
    WITH CHECK (status = 'pending' AND ({MEMBER} OR (workspace_id IS NULL AND {CTX_ADMIN})));
-- Members only withdraw their own requests (superseded); deciding is the admins'.
CREATE POLICY private_network_requests_update ON private_network_requests FOR UPDATE TO vv_app
    USING ({MEMBER} OR {CTX_ADMIN})
    WITH CHECK ({CTX_ADMIN} OR ({MEMBER} AND status = 'superseded'));
CREATE POLICY private_network_requests_worker ON private_network_requests FOR SELECT
    TO vv_worker USING (workspace_id IS NULL OR {MEMBER});

ALTER TABLE connectors
    DROP COLUMN private_network_approved_by,
    DROP COLUMN private_network_approved_at;

ALTER TABLE secrets DROP CONSTRAINT ck_secrets_global_purpose;
ALTER TABLE secrets ADD CONSTRAINT ck_secrets_global_purpose
    CHECK (workspace_id IS NOT NULL OR purpose IN ('llm', 'source', 'connector'));

-- Global publication connectors are targets for every team (Q40): members of a
-- workspace read them (configuration only; secrets stay in the vault).
CREATE POLICY connectors_publish_global ON connectors FOR SELECT TO vv_app
    USING (workspace_id IS NULL AND family = 'publish' AND cardinality({CTX_WORKSPACES}) > 0);
"""

DOWNGRADE = """
DROP POLICY IF EXISTS connectors_publish_global ON connectors;
DELETE FROM secrets WHERE workspace_id IS NULL AND purpose = 'connector';
ALTER TABLE secrets DROP CONSTRAINT ck_secrets_global_purpose;
ALTER TABLE secrets ADD CONSTRAINT ck_secrets_global_purpose
    CHECK (workspace_id IS NOT NULL OR purpose IN ('llm', 'source'));
ALTER TABLE connectors
    ADD COLUMN private_network_approved_by uuid REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN private_network_approved_at timestamptz;
DROP TABLE IF EXISTS private_network_requests;
ALTER TABLE bulletin_settings
    DROP COLUMN csaf_publisher_name,
    DROP COLUMN csaf_publisher_namespace,
    DROP COLUMN csaf_publisher_category;
"""


def upgrade() -> None:
    execute_script(UPGRADE)


def downgrade() -> None:
    execute_script(DOWNGRADE)
