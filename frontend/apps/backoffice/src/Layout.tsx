import { hasPermission, SignOutButton, StepUpProvider, useMe } from "@vv/auth";
import { Alert, AppShell } from "@vv/ui";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router";

export function Layout() {
  const { t } = useTranslation();
  const me = useMe().data;
  const can = (permission: string) => hasPermission(me, permission);
  return (
    <StepUpProvider>
      <AppShell
        title={t("app.title")}
        subtitle={t("app.subtitle")}
        nav={
          <>
            <NavLink to="/" end>
              {t("nav.home")}
            </NavLink>
            {can("iam.users.manage") ? <NavLink to="/admin/users">{t("nav.users")}</NavLink> : null}
            {can("iam.clients.manage") ? (
              <NavLink to="/admin/clients">{t("nav.clients")}</NavLink>
            ) : null}
            {can("iam.workspaces.manage") ? (
              <NavLink to="/admin/workspaces">{t("nav.workspaces")}</NavLink>
            ) : null}
            {can("audit.read_global") ? (
              <NavLink to="/admin/audit">{t("nav.audit")}</NavLink>
            ) : null}
            <NavLink to="/account">{t("nav.account")}</NavLink>
          </>
        }
        actions={
          <>
            <span className="vv-muted">{me?.display_name}</span>
            <SignOutButton />
          </>
        }
      >
        <Outlet />
      </AppShell>
    </StepUpProvider>
  );
}

/** Hides a section from users without the permission. The API enforces it regardless. */
export function RequirePermission({ permission }: { permission: string }) {
  const { t } = useTranslation();
  const me = useMe().data;
  return hasPermission(me, permission) ? <Outlet /> : <Alert>{t("errors.forbidden")}</Alert>;
}
