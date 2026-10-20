import { hasPermission, SignOutButton, StepUpProvider, useMe } from "@vv/auth";
import { Alert, AppShell } from "@vv/ui";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router";

export function Layout() {
  const { t } = useTranslation();
  const me = useMe().data;
  return (
    <StepUpProvider>
      <AppShell
        title={t("app.title")}
        subtitle={me?.client_org?.name ?? t("app.subtitle")}
        nav={
          <>
            <NavLink to="/" end>
              {t("nav.bulletins")}
            </NavLink>
            {hasPermission(me, "portal.org_users.manage") ? (
              <NavLink to="/organization">{t("nav.organization")}</NavLink>
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
