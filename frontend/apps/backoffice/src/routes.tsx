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

import { Layout, RequirePermission, RequireWorkspacePermission } from "./Layout";
import { AuditPage } from "./pages/admin/AuditPage";
import { ClientDetailPage, ClientsPage } from "./pages/admin/ClientsPage";
import { UserDetailPage } from "./pages/admin/UserDetailPage";
import { UsersPage } from "./pages/admin/UsersPage";
import { WorkspacesPage } from "./pages/admin/WorkspacesPage";
import { CvesPage } from "./pages/catalog/CvesPage";
import { ConnectorsPage } from "./pages/connectors/ConnectorsPage";
import { HomePage } from "./pages/HomePage";
import { SecretsPage } from "./pages/secrets/SecretsPage";
import { TechnologiesPage } from "./pages/technologies/TechnologiesPage";
import { VulnerabilitiesPage } from "./pages/vulns/VulnerabilitiesPage";
import { VulnerabilityPage } from "./pages/vulns/VulnerabilityPage";
import { ScopePage } from "./pages/watch/ScopePage";
import { SourcesPage } from "./pages/watch/SourcesPage";

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
            element: <RequirePermission permission="vuln.read" />,
            children: [
              { path: "/vulnerabilities", element: <VulnerabilitiesPage /> },
              { path: "/vulnerabilities/:ref", element: <VulnerabilityPage /> },
              { path: "/cves", element: <CvesPage /> },
              { path: "/technologies", element: <TechnologiesPage /> },
            ],
          },
          {
            element: <RequireWorkspacePermission permission="watch_scope.manage" />,
            children: [{ path: "/watch-scope", element: <ScopePage /> }],
          },
          {
            element: <RequireWorkspacePermission permission="source.manage" />,
            children: [{ path: "/sources", element: <SourcesPage /> }],
          },
          {
            element: <RequireWorkspacePermission permission="connector.source.manage" />,
            children: [{ path: "/connectors", element: <ConnectorsPage scope="workspace" /> }],
          },
          {
            element: <RequireWorkspacePermission permission="secret.manage" />,
            children: [{ path: "/secrets", element: <SecretsPage scope="workspace" /> }],
          },
          {
            element: <RequirePermission permission="connector.global.manage" />,
            children: [
              { path: "/admin/connectors", element: <ConnectorsPage scope="global" /> },
              { path: "/admin/secrets", element: <SecretsPage scope="global" /> },
            ],
          },
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
