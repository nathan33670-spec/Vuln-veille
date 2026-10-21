import { hasPermission, SignOutButton, StepUpProvider, useMe } from "@vv/auth";
import { Alert, AppShell } from "@vv/ui";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router";

import { useWorkspace, WorkspaceProvider, WorkspaceSwitcher } from "./workspace";

export function Layout() {
  return (
    <StepUpProvider>
      <WorkspaceProvider>
        <Shell />
      </WorkspaceProvider>
    </StepUpProvider>
  );
}

function Shell() {
  const { t } = useTranslation();
  const me = useMe().data;
  const { can: canInWorkspace } = useWorkspace();
  const can = (permission: string) => hasPermission(me, permission);
  const link = (to: string, label: string, end = false) => (
    <NavLink key={to} to={to} end={end}>
      {label}
    </NavLink>
  );
  return (
    <AppShell
      title={t("app.title")}
      subtitle={t("app.subtitle")}
      nav={
        <>
          {link("/", t("nav.home"), true)}
          {can("vuln.read") ? link("/vulnerabilities", t("nav.vulnerabilities")) : null}
          {can("vuln.read") ? link("/cves", t("nav.cves")) : null}
          {canInWorkspace("watch_scope.manage") ? link("/watch-scope", t("nav.scope")) : null}
          {canInWorkspace("source.manage") ? link("/sources", t("nav.sources")) : null}
          {can("vuln.read") ? link("/technologies", t("nav.technologies")) : null}
          {canInWorkspace("connector.source.manage")
            ? link("/connectors", t("nav.connectors"))
            : null}
          {canInWorkspace("secret.manage") ? link("/secrets", t("nav.secrets")) : null}
          {can("iam.users.manage") ? link("/admin/users", t("nav.users")) : null}
          {can("iam.clients.manage") ? link("/admin/clients", t("nav.clients")) : null}
          {can("iam.workspaces.manage") ? link("/admin/workspaces", t("nav.workspaces")) : null}
          {can("connector.global.manage")
            ? link("/admin/connectors", t("nav.globalConnectors"))
            : null}
          {can("connector.global.manage") ? link("/admin/secrets", t("nav.globalSecrets")) : null}
          {can("audit.read_global") ? link("/admin/audit", t("nav.audit")) : null}
          {link("/account", t("nav.account"))}
        </>
      }
      actions={
        <>
          <WorkspaceSwitcher />
          <span className="vv-muted">{me?.display_name}</span>
          <SignOutButton />
        </>
      }
    >
      <Outlet />
    </AppShell>
  );
}

/** Hides a section from users without the permission. The API enforces it regardless. */
export function RequirePermission({ permission }: { permission: string }) {
  const { t } = useTranslation();
  const me = useMe().data;
  return hasPermission(me, permission) ? <Outlet /> : <Alert>{t("errors.forbidden")}</Alert>;
}

/** Same, for a permission in the current workspace (VOC or CERT). */
export function RequireWorkspacePermission({ permission }: { permission: string }) {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  if (!slug) return <Alert tone="info">{t("workspace.none")}</Alert>;
  return can(permission) ? <Outlet /> : <Alert>{t("errors.forbidden")}</Alert>;
}
