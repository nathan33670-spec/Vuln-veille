"""Portal delivery: platform branding and e-mail preferences (phase 8, 8B, Q44 to Q46).

- ``platform_branding``: one row, the issuer's name and logo (PNG re-encoded by the
  API) shown on the portal and in the PDFs (Q46). Public information: the portal role
  reads it.
- ``portal_notification_preferences``: each client user chooses to receive the
  bulletins by e-mail (Q44); the portal role reads and writes its own row only, the
  worker reads them to address the messages.

Revision ID: 0020_portal_delivery
Revises: 0019_portal
Create Date: 2026-11-06 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0020_portal_delivery"
down_revision: str | None = "0019_portal"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CTX_USER = "nullif(current_setting('app.user_id', true), '')::uuid"

UPGRADE = f"""
CREATE TABLE platform_branding (
    id smallint PRIMARY KEY CHECK (id = 1),
    issuer_name text NOT NULL DEFAULT '' CHECK (length(issuer_name) <= 120),
    logo_png bytea CHECK (octet_length(logo_png) <= 307200),
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1
);
INSERT INTO platform_branding (id) VALUES (1);
REVOKE INSERT, DELETE, TRUNCATE ON platform_branding FROM vv_app, vv_worker;
REVOKE UPDATE ON platform_branding FROM vv_worker;
GRANT SELECT ON platform_branding TO vv_portal;

CREATE TABLE portal_notification_preferences (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    email_bulletins boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON portal_notification_preferences FROM vv_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON portal_notification_preferences FROM vv_worker;
GRANT SELECT, INSERT, UPDATE ON portal_notification_preferences TO vv_portal;
ALTER TABLE portal_notification_preferences ENABLE ROW LEVEL SECURITY;
CREATE POLICY portal_notification_preferences_own ON portal_notification_preferences
    TO vv_portal USING (user_id = {CTX_USER}) WITH CHECK (user_id = {CTX_USER});
CREATE POLICY portal_notification_preferences_worker ON portal_notification_preferences
    FOR SELECT TO vv_worker USING (true);
"""

DOWNGRADE = "DROP TABLE IF EXISTS portal_notification_preferences, platform_branding;"


def upgrade() -> None:
    execute_script(UPGRADE)


def downgrade() -> None:
    execute_script(DOWNGRADE)
