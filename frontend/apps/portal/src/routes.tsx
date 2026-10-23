import {
  AccountPage,
  ForgotPasswordPage,
  InvitationPage,
  LoginPage,
  MfaEnrollPage,
  MfaVerifyPage,
  RequireAuth,
  ResetPasswordPage,
  RouteErrorPage,
} from "@vv/auth";
import type { RouteObject } from "react-router";

import { Layout, RequirePermission } from "./Layout";
import { BulletinPage } from "./pages/bulletins/BulletinPage";
import { BulletinsPage } from "./pages/bulletins/BulletinsPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { OrgUsersPage } from "./pages/OrgUsersPage";

const pages: RouteObject[] = [
  { path: "/login", element: <LoginPage /> },
  { path: "/mfa", element: <MfaVerifyPage /> },
  { path: "/mfa/enroll", element: <MfaEnrollPage /> },
  { path: "/invitation", element: <InvitationPage /> },
  { path: "/forgot-password", element: <ForgotPasswordPage /> },
  { path: "/reset-password", element: <ResetPasswordPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <Layout />,
        children: [
          { path: "/", element: <BulletinsPage /> },
          { path: "/bulletins/:id", element: <BulletinPage /> },
          { path: "/notifications", element: <NotificationsPage /> },
          { path: "/account", element: <AccountPage /> },
          {
            element: <RequirePermission permission="portal.org_users.manage" />,
            children: [{ path: "/organization", element: <OrgUsersPage /> }],
          },
        ],
      },
    ],
  },
];

export const routes: RouteObject[] = [{ errorElement: <RouteErrorPage />, children: pages }];
