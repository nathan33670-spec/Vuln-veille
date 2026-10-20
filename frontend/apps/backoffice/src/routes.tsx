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
import { AuditPage } from "./pages/admin/AuditPage";
import { ClientDetailPage, ClientsPage } from "./pages/admin/ClientsPage";
import { UserDetailPage } from "./pages/admin/UserDetailPage";
import { UsersPage } from "./pages/admin/UsersPage";
import { WorkspacesPage } from "./pages/admin/WorkspacesPage";
import { HomePage } from "./pages/HomePage";

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
            element: <RequirePermission permission="iam.users.manage" />,
            children: [
              { path: "/admin/users", element: <UsersPage /> },
              { path: "/admin/users/:userId", element: <UserDetailPage /> },
            ],
          },
          {
            element: <RequirePermission permission="iam.workspaces.manage" />,
            children: [{ path: "/admin/workspaces", element: <WorkspacesPage /> }],
          },
          {
            element: <RequirePermission permission="iam.clients.manage" />,
            children: [
              { path: "/admin/clients", element: <ClientsPage /> },
              { path: "/admin/clients/:orgId", element: <ClientDetailPage /> },
            ],
          },
          {
            element: <RequirePermission permission="audit.read_global" />,
            children: [{ path: "/admin/audit", element: <AuditPage /> }],
          },
        ],
      },
    ],
  },
];

export const routes: RouteObject[] = [{ errorElement: <RouteErrorPage />, children: pages }];
