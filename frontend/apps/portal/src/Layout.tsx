import { unwrap } from "@vv/api-client";
import { hasPermission, SignOutButton, StepUpProvider, useMe } from "@vv/auth";
import { Alert, AppShell } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router";

import { client } from "./api";

export function Layout() {
  const { t } = useTranslation();
  const me = useMe().data;
  // The issuer's name and logo (platform branding, Q46); the logo is a PNG the
  // server re-encoded, served from the same origin.
  const branding = useQuery({
    queryKey: ["branding"],
    queryFn: async () => unwrap(await client.GET("/api/portal/v1/branding")),
    staleTime: 5 * 60_000,
  }).data;
  return (
    <StepUpProvider>
      <AppShell
        title={branding?.issuer_name || t("app.title")}
        subtitle={me?.client_org?.name ?? t("app.subtitle")}
        brand={
          branding?.has_logo ? (
            <img
              className="vv-brand-logo"
              alt=""
              src={`/api/portal/v1/branding/logo?v=${branding.version}`}
            />
          ) : null
        }
        nav={
          <>
            <NavLink to="/" end>
              {t("nav.bulletins")}
            </NavLink>
            {hasPermission(me, "portal.org_users.manage") ? (
              <NavLink to="/organization">{t("nav.organization")}</NavLink>
            ) : null}
            <NavLink to="/notifications">{t("nav.notifications")}</NavLink>
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
