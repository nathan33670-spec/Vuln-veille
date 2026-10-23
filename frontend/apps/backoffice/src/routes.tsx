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
import { BrandingPage } from "./pages/admin/BrandingPage";
import { ClientDetailPage, ClientsPage } from "./pages/admin/ClientsPage";
import { UserDetailPage } from "./pages/admin/UserDetailPage";
import { UsersPage } from "./pages/admin/UsersPage";
import { WorkspacesPage } from "./pages/admin/WorkspacesPage";
import { AgentPage } from "./pages/ai/AgentPage";
import { AgentRunPage } from "./pages/ai/AgentRunPage";
import { AgentsPage } from "./pages/ai/AgentsPage";
import { AiEnginePage } from "./pages/ai/AiEnginePage";
import { EvaluationPage } from "./pages/ai/EvaluationPage";
import { XCoveragePage } from "./pages/ai/XCoveragePage";
import { CvesPage } from "./pages/catalog/CvesPage";
import { ConnectorsPage } from "./pages/connectors/ConnectorsPage";
import { BulletinPage } from "./pages/bulletins/BulletinPage";
import { BulletinsPage } from "./pages/bulletins/BulletinsPage";
import { TemplatePage } from "./pages/bulletins/TemplatePage";
import { TemplatesPage } from "./pages/bulletins/TemplatesPage";
import { HomePage } from "./pages/HomePage";
import { PrivateNetworkPage } from "./pages/publish/PrivateNetworkPage";
import { PublishConnectorPage } from "./pages/publish/PublishConnectorPage";
import { PublishConnectorsPage } from "./pages/publish/PublishConnectorsPage";
import { SecretsPage } from "./pages/secrets/SecretsPage";
import { TechnologiesPage } from "./pages/technologies/TechnologiesPage";
import { VulnerabilitiesPage } from "./pages/vulns/VulnerabilitiesPage";
import { VulnerabilityPage } from "./pages/vulns/VulnerabilityPage";
import { ScopePage } from "./pages/watch/ScopePage";
import { RunPage } from "./pages/workflows/RunPage";
import { WorkflowPage } from "./pages/workflows/WorkflowPage";
import { WorkflowsPage } from "./pages/workflows/WorkflowsPage";
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
            element: <RequireWorkspacePermission permission="workflow.read" />,
            children: [
              { path: "/workflows", element: <WorkflowsPage /> },
              { path: "/workflows/:id", element: <WorkflowPage /> },
              {
                // Loaded on demand: the canvas library stays out of the main bundle.
                path: "/workflows/:id/edit",
                lazy: async () => ({
                  Component: (await import("./pages/workflows/editor/EditorPage")).EditorPage,
                }),
              },
              {
                path: "/workflows/:id/compare",
                lazy: async () => ({
                  Component: (await import("./pages/workflows/editor/ComparePage")).ComparePage,
                }),
              },
              { path: "/runs/:id", element: <RunPage /> },
              { path: "/agents", element: <AgentsPage /> },
              { path: "/agents/:id", element: <AgentPage /> },
              { path: "/agent-runs/:id", element: <AgentRunPage /> },
              { path: "/ai-evaluation", element: <EvaluationPage /> },
              { path: "/x-coverage", element: <XCoveragePage /> },
            ],
          },
          {
            element: <RequireWorkspacePermission permission="bulletin.draft" />,
            children: [
              { path: "/bulletins", element: <BulletinsPage /> },
              { path: "/bulletins/:id", element: <BulletinPage /> },
              { path: "/bulletin-templates", element: <TemplatesPage /> },
              { path: "/bulletin-templates/:id", element: <TemplatePage /> },
            ],
          },
          {
            element: <RequireWorkspacePermission permission="connector.publish.push" />,
            children: [{ path: "/publish-connectors", element: <PublishConnectorsPage /> }],
          },
          {
            element: <RequireWorkspacePermission permission="connector.publish.manage" />,
            children: [
              {
                path: "/publish-connectors/:id",
                element: <PublishConnectorPage scope="workspace" />,
              },
            ],
          },
          {
            element: <RequireWorkspacePermission permission="ai.engine.manage" />,
            children: [{ path: "/ai-engine", element: <AiEnginePage /> }],
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
              {
                path: "/admin/publish-connectors/:id",
                element: <PublishConnectorPage scope="global" />,
              },
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
            element: <RequirePermission permission="connector.allow_private_network" />,
            children: [{ path: "/admin/private-network", element: <PrivateNetworkPage /> }],
          },
          {
            element: <RequirePermission permission="platform.branding.manage" />,
            children: [{ path: "/admin/branding", element: <BrandingPage /> }],
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
