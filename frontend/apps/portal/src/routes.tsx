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
import { HomePage } from "./pages/HomePage";
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
          { path: "/", element: <HomePage /> },
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
