"""Identity, access and audit (phase 1).

Tables of spec 01 §1 and §2 (audit), the two seeded workspaces, the hash-chained
audit function, grants and Row-Level Security policies.

RLS model (SECURITY.md §4.3):
- ``vv_app`` (back-office) sees all identity rows; audit rows are filtered by the
  request context (platform admin, or member of the event's workspace);
- ``vv_portal`` only sees client rows reachable from its request context
  (``app.user_id``, ``app.client_org_id``, ``app.login_email``, ``app.token_hash``,
  ``app.session_hash``), set per transaction by the API;
- audit rows are written only through ``audit_append`` (SECURITY DEFINER).

Revision ID: 0002_iam
Revises: 0001_baseline
Create Date: 2026-10-21 09:00:00
"""

from collections.abc import Sequence

from app.core.migrations import execute_script

revision: str = "0002_iam"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Helpers reading the per-transaction request context (NULL when unset).
CTX_USER = "nullif(current_setting('app.user_id', true), '')::uuid"
CTX_ORG = "nullif(current_setting('app.client_org_id', true), '')::uuid"
CTX_EMAIL = "nullif(current_setting('app.login_email', true), '')::citext"
CTX_TOKEN = "nullif(current_setting('app.token_hash', true), '')"
CTX_SESSION = "nullif(current_setting('app.session_hash', true), '')"
CTX_ADMIN = "current_setting('app.is_platform_admin', true) = 'true'"
CTX_WORKSPACES = "coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[]"

TABLES = """
CREATE TABLE users (
    id uuid PRIMARY KEY,
    email citext NOT NULL UNIQUE CHECK (length(email) <= 254),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    user_type text NOT NULL CHECK (user_type IN ('internal', 'client')),
    status text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited', 'active', 'disabled')),
    password_hash text,
    password_changed_at timestamptz,
    failed_login_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    last_login_at timestamptz,
    locale text NOT NULL DEFAULT 'fr' CHECK (locale IN ('fr', 'en')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_global_roles (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('platform_admin')),
    granted_by uuid REFERENCES users (id) ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role)
);

CREATE TABLE user_mfa_totp (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret_enc bytea NOT NULL,
    confirmed_at timestamptz,
    last_used_step bigint,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_recovery_codes (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash text NOT NULL UNIQUE,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_user_recovery_codes_user_id ON user_recovery_codes (user_id);

CREATE TABLE sessions (
    id_hash text PRIMARY KEY,
    public_id uuid NOT NULL UNIQUE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    audience text NOT NULL CHECK (audience IN ('backoffice', 'portal')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    mfa_verified_at timestamptz,
    mfa_enrollment_required boolean NOT NULL DEFAULT false,
    step_up_at timestamptz,
    mfa_attempts integer NOT NULL DEFAULT 0,
    ip inet,
    user_agent text CHECK (length(user_agent) <= 512),
    revoked_at timestamptz
);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);

CREATE TABLE auth_tokens (
    id uuid PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('invitation', 'password_reset')),
    -- Application whose link carries the token; the portal can only see 'portal' tokens.
    audience text NOT NULL CHECK (audience IN ('backoffice', 'portal')),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_auth_tokens_user_id ON auth_tokens (user_id);

CREATE TABLE workspaces (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z][a-z0-9-]{1,30}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    grants_platform_admin boolean NOT NULL DEFAULT false,
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_memberships (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('analyst', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, workspace_id)
);
CREATE INDEX ix_workspace_memberships_workspace_id ON workspace_memberships (workspace_id);

CREATE TABLE client_organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 120),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE client_memberships (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    client_org_id uuid NOT NULL REFERENCES client_organizations (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('client_user', 'client_admin')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_client_memberships_client_org_id ON client_memberships (client_org_id);

CREATE TABLE audit_events (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'system', 'workflow', 'anonymous')),
    actor_user_id uuid,
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{2,80}$'),
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    target_type text,
    target_id text,
    workspace_id uuid,
    client_org_id uuid,
    ip inet,
    request_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash text NOT NULL,
    hash text NOT NULL UNIQUE
);
CREATE INDEX ix_audit_events_occurred_at ON audit_events (occurred_at);
CREATE INDEX ix_audit_events_workspace_id ON audit_events (workspace_id);
CREATE INDEX ix_audit_events_actor_user_id ON audit_events (actor_user_id);
"""

SEED = """
INSERT INTO workspaces (id, slug, name, grants_platform_admin) VALUES
    ('01900000-0000-7000-8000-000000000001', 'voc', 'VOC', true),
    ('01900000-0000-7000-8000-000000000002', 'cert', 'CERT', false);
"""

AUDIT_FUNCTIONS = """
CREATE FUNCTION audit_digest(
    p_prev_hash text, p_occurred_at timestamptz, p_actor_type text, p_actor_user_id uuid,
    p_action text, p_outcome text, p_target_type text, p_target_id text, p_workspace_id uuid,
    p_client_org_id uuid, p_ip inet, p_request_id text, p_details jsonb
) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, public
AS $$
    SELECT encode(sha256(convert_to(p_prev_hash || jsonb_build_object(
        'occurred_at', to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'actor_type', p_actor_type, 'actor_user_id', p_actor_user_id,
        'action', p_action, 'outcome', p_outcome,
        'target_type', p_target_type, 'target_id', p_target_id,
        'workspace_id', p_workspace_id, 'client_org_id', p_client_org_id,
        'ip', host(p_ip), 'request_id', p_request_id, 'details', p_details
    )::text, 'UTF8')), 'hex')
$$;

CREATE FUNCTION audit_append(
    p_actor_type text, p_actor_user_id uuid, p_action text, p_outcome text,
    p_target_type text, p_target_id text, p_workspace_id uuid, p_client_org_id uuid,
    p_ip inet, p_request_id text, p_details jsonb
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_prev text;
    v_at timestamptz := date_trunc('microseconds', clock_timestamp());
    v_details jsonb := coalesce(p_details, '{}'::jsonb);
    v_id bigint;
BEGIN
    -- Serializes writers so that each row chains to the previous one.
    PERFORM pg_advisory_xact_lock(1448361986);
    SELECT hash INTO v_prev FROM audit_events ORDER BY id DESC LIMIT 1;
    v_prev := coalesce(v_prev, repeat('0', 64));
    INSERT INTO audit_events (
        occurred_at, actor_type, actor_user_id, action, outcome, target_type, target_id,
        workspace_id, client_org_id, ip, request_id, details, prev_hash, hash
    ) VALUES (
        v_at, p_actor_type, p_actor_user_id, p_action, p_outcome, p_target_type, p_target_id,
        p_workspace_id, p_client_org_id, p_ip, p_request_id, v_details, v_prev,
        audit_digest(v_prev, v_at, p_actor_type, p_actor_user_id, p_action, p_outcome,
                     p_target_type, p_target_id, p_workspace_id, p_client_org_id, p_ip,
                     p_request_id, v_details)
    ) RETURNING id INTO v_id;
    RETURN v_id;
END
$$;

-- Returns the id of the first row whose hash or link is wrong, or NULL if the chain holds.
CREATE FUNCTION audit_verify() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    r audit_events%ROWTYPE;
    v_prev text := repeat('0', 64);
BEGIN
    FOR r IN SELECT * FROM audit_events ORDER BY id LOOP
        IF r.prev_hash <> v_prev OR r.hash <> audit_digest(
            r.prev_hash, r.occurred_at, r.actor_type, r.actor_user_id, r.action, r.outcome,
            r.target_type, r.target_id, r.workspace_id, r.client_org_id, r.ip, r.request_id,
            r.details
        ) THEN
            RETURN r.id;
        END IF;
        v_prev := r.hash;
    END LOOP;
    RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION audit_append(text, uuid, text, text, text, text, uuid, uuid, inet, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_verify() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_append(text, uuid, text, text, text, text, uuid, uuid, inet, text, jsonb)
    TO vv_app, vv_worker, vv_portal;
GRANT EXECUTE ON FUNCTION audit_verify() TO vv_app;
"""

# Default privileges already give vv_app and vv_worker DML on new tables (app.db_roles).
GRANTS = """
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_events FROM vv_app, vv_worker;
REVOKE ALL ON SEQUENCE audit_events_id_seq FROM vv_app, vv_worker;
REVOKE INSERT, DELETE, TRUNCATE ON workspaces FROM vv_app, vv_worker;

GRANT SELECT, INSERT, UPDATE ON users, sessions, auth_tokens, client_memberships TO vv_portal;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_mfa_totp, user_recovery_codes TO vv_portal;
GRANT SELECT ON client_organizations TO vv_portal;
"""

CLIENT_USER = "user_id IN (SELECT id FROM users WHERE user_type = 'client')"

POLICIES = f"""
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_internal ON users TO vv_app, vv_worker USING (true) WITH CHECK (true);
CREATE POLICY users_portal ON users TO vv_portal
    USING (user_type = 'client' AND (
        email = {CTX_EMAIL}
        OR id = {CTX_USER}
        OR id IN (SELECT user_id FROM client_memberships WHERE client_org_id = {CTX_ORG})
    ))
    WITH CHECK (user_type = 'client');

ALTER TABLE client_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY client_memberships_internal ON client_memberships TO vv_app, vv_worker
    USING (true) WITH CHECK (true);
CREATE POLICY client_memberships_portal ON client_memberships TO vv_portal
    USING (client_org_id = {CTX_ORG} OR user_id = {CTX_USER})
    WITH CHECK (client_org_id = {CTX_ORG});

ALTER TABLE client_organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY client_organizations_internal ON client_organizations TO vv_app, vv_worker
    USING (true) WITH CHECK (true);
CREATE POLICY client_organizations_portal ON client_organizations TO vv_portal
    USING (id = {CTX_ORG}
           OR id IN (SELECT client_org_id FROM client_memberships WHERE user_id = {CTX_USER}));

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY sessions_internal ON sessions TO vv_app, vv_worker USING (true) WITH CHECK (true);
CREATE POLICY sessions_portal ON sessions TO vv_portal
    USING (audience = 'portal' AND (id_hash = {CTX_SESSION} OR user_id = {CTX_USER}))
    WITH CHECK (audience = 'portal' AND {CLIENT_USER});

ALTER TABLE auth_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth_tokens_internal ON auth_tokens TO vv_app, vv_worker USING (true) WITH CHECK (true);
CREATE POLICY auth_tokens_portal ON auth_tokens TO vv_portal
    USING (audience = 'portal' AND (
        token_hash = {CTX_TOKEN}
        OR user_id = {CTX_USER}
        -- client admins re-issue invitations of their organization's users
        OR user_id IN (SELECT user_id FROM client_memberships WHERE client_org_id = {CTX_ORG})
    ))
    WITH CHECK (audience = 'portal' AND {CLIENT_USER});

ALTER TABLE user_mfa_totp ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_mfa_totp_internal ON user_mfa_totp TO vv_app, vv_worker USING (true) WITH CHECK (true);
CREATE POLICY user_mfa_totp_portal ON user_mfa_totp TO vv_portal
    USING (user_id = {CTX_USER} AND {CLIENT_USER}) WITH CHECK (user_id = {CTX_USER} AND {CLIENT_USER});

ALTER TABLE user_recovery_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_recovery_codes_internal ON user_recovery_codes TO vv_app, vv_worker
    USING (true) WITH CHECK (true);
CREATE POLICY user_recovery_codes_portal ON user_recovery_codes TO vv_portal
    USING (user_id = {CTX_USER} AND {CLIENT_USER}) WITH CHECK (user_id = {CTX_USER} AND {CLIENT_USER});

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_events_read ON audit_events FOR SELECT TO vv_app
    USING ({CTX_ADMIN} OR workspace_id = ANY ({CTX_WORKSPACES}));
"""


def upgrade() -> None:
    for script in (TABLES, SEED, AUDIT_FUNCTIONS, GRANTS, POLICIES):
        execute_script(script)


def downgrade() -> None:
    execute_script(
        """
        DROP FUNCTION IF EXISTS audit_verify();
        DROP FUNCTION IF EXISTS audit_append(text, uuid, text, text, text, text, uuid, uuid,
                                             inet, text, jsonb);
        DROP FUNCTION IF EXISTS audit_digest(text, timestamptz, text, uuid, text, text, text,
                                             text, uuid, uuid, inet, text, jsonb);
        DROP TABLE IF EXISTS audit_events, client_memberships, client_organizations,
            workspace_memberships, workspaces, auth_tokens, sessions, user_recovery_codes,
            user_mfa_totp, user_global_roles, users;
        """
    )
