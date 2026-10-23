"""Permission catalogue and role bundles (RBAC.md §3-4).

Permissions and roles are defined in code, not in the database, so that no data
change can escalate privileges. Code always checks permissions, never role names.
"""

from enum import StrEnum


class Permission(StrEnum):
    # Global (platform)
    IAM_USERS_MANAGE = "iam.users.manage"
    IAM_ROLES_MANAGE = "iam.roles.manage"
    IAM_WORKSPACES_MANAGE = "iam.workspaces.manage"
    IAM_CLIENTS_MANAGE = "iam.clients.manage"
    SECURITY_SETTINGS_MANAGE = "security.settings.manage"
    AUDIT_READ_GLOBAL = "audit.read_global"
    TECHNOLOGY_MANAGE = "technology.manage"
    TECHNOLOGY_MERGE_DELETE = "technology.merge_delete"
    TECHNOLOGY_REQUEST_REVIEW = "technology_request.review"
    CONNECTOR_GLOBAL_MANAGE = "connector.global.manage"
    AI_DEFAULT_ENGINE_MANAGE = "ai.default_engine.manage"
    CONNECTOR_ALLOW_PRIVATE_NETWORK = "connector.allow_private_network"
    PLATFORM_BRANDING_MANAGE = "platform.branding.manage"
    VULN_READ = "vuln.read"  # shared vulnerability records (ADR-024)

    # Workspace
    WORKSPACE_SETTINGS_MANAGE = "workspace.settings.manage"
    WORKSPACE_AUDIT_READ = "workspace.audit.read"
    WATCH_SCOPE_MANAGE = "watch_scope.manage"
    CONNECTOR_SOURCE_MANAGE = "connector.source.manage"
    SOURCE_MANAGE = "source.manage"
    SECRET_MANAGE = "secret.manage"  # noqa: S105 - permission name, not a secret
    VULN_QUALIFY = "vuln.qualify"
    WORKFLOW_READ = "workflow.read"
    WORKFLOW_EDIT = "workflow.edit"
    WORKFLOW_RUN = "workflow.run"
    AI_ENGINE_MANAGE = "ai.engine.manage"
    AI_AGENT_MANAGE = "ai.agent.manage"
    AI_AGENT_RUN = "ai.agent.run"
    AI_EVALUATION_RUN = "ai.evaluation.run"
    TEMPLATE_MANAGE = "template.manage"
    BULLETIN_DRAFT = "bulletin.draft"
    BULLETIN_REVIEW = "bulletin.review"
    BULLETIN_PUBLISH = "bulletin.publish"
    CONNECTOR_PUBLISH_MANAGE = "connector.publish.manage"
    CONNECTOR_PUBLISH_PUSH = "connector.publish.push"

    # Client organization (portal)
    PORTAL_BULLETINS_READ = "portal.bulletins.read"
    PORTAL_SUBSCRIPTIONS_MANAGE = "portal.subscriptions.manage"
    PORTAL_TECHNOLOGY_REQUEST_CREATE = "portal.technology_request.create"
    PORTAL_ORG_USERS_MANAGE = "portal.org_users.manage"


P = Permission

PLATFORM_ADMIN: frozenset[Permission] = frozenset(
    {
        P.IAM_USERS_MANAGE,
        P.IAM_ROLES_MANAGE,
        P.IAM_WORKSPACES_MANAGE,
        P.IAM_CLIENTS_MANAGE,
        P.SECURITY_SETTINGS_MANAGE,
        P.AUDIT_READ_GLOBAL,
        P.TECHNOLOGY_MANAGE,
        P.TECHNOLOGY_MERGE_DELETE,
        P.TECHNOLOGY_REQUEST_REVIEW,
        P.CONNECTOR_GLOBAL_MANAGE,
        P.AI_DEFAULT_ENGINE_MANAGE,
        P.CONNECTOR_ALLOW_PRIVATE_NETWORK,
        P.PLATFORM_BRANDING_MANAGE,
    }
)

# Granted inside the member's workspace.
WORKSPACE_ROLES: dict[str, frozenset[Permission]] = {
    "analyst": frozenset(
        {
            P.WORKSPACE_SETTINGS_MANAGE,
            P.WORKSPACE_AUDIT_READ,
            P.WATCH_SCOPE_MANAGE,
            P.CONNECTOR_SOURCE_MANAGE,
            P.SOURCE_MANAGE,
            P.SECRET_MANAGE,
            P.VULN_QUALIFY,
            P.WORKFLOW_READ,
            P.WORKFLOW_EDIT,
            P.WORKFLOW_RUN,
            P.AI_ENGINE_MANAGE,
            P.AI_AGENT_MANAGE,
            P.AI_AGENT_RUN,
            P.AI_EVALUATION_RUN,
            P.TEMPLATE_MANAGE,
            P.BULLETIN_DRAFT,
            P.BULLETIN_REVIEW,
            P.BULLETIN_PUBLISH,
            P.CONNECTOR_PUBLISH_MANAGE,
            P.CONNECTOR_PUBLISH_PUSH,
        }
    ),
    "viewer": frozenset({P.WORKFLOW_READ}),
}

# Global permissions that any workspace membership brings.
MEMBERSHIP_GLOBAL: dict[str, frozenset[Permission]] = {
    "analyst": frozenset({P.VULN_READ, P.TECHNOLOGY_MANAGE}),
    "viewer": frozenset({P.VULN_READ}),
}

CLIENT_ROLES: dict[str, frozenset[Permission]] = {
    "client_user": frozenset(
        {P.PORTAL_BULLETINS_READ, P.PORTAL_SUBSCRIPTIONS_MANAGE, P.PORTAL_TECHNOLOGY_REQUEST_CREATE}
    ),
    "client_admin": frozenset(
        {
            P.PORTAL_BULLETINS_READ,
            P.PORTAL_SUBSCRIPTIONS_MANAGE,
            P.PORTAL_TECHNOLOGY_REQUEST_CREATE,
            P.PORTAL_ORG_USERS_MANAGE,
        }
    ),
}

GLOBAL_ROLES = ("platform_admin",)
