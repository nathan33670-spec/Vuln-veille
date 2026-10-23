import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import { routes } from "./routes";

afterEach(() => {
  vi.unstubAllGlobals();
});

const me = {
  id: "u-eve",
  email: "eve@example.com",
  display_name: "Eve",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions: ["vuln.read", "connector.allow_private_network"],
  workspaces: [
    {
      slug: "cert",
      name: "CERT",
      role: "analyst",
      permissions: [
        "bulletin.draft",
        "bulletin.review",
        "bulletin.publish",
        "connector.publish.manage",
        "connector.publish.push",
        "secret.manage",
      ],
    },
  ],
  client_org: null,
};

type Call = { method: string; path: string; body: unknown };
type Handler = (path: string, method: string, body: unknown) => Response | undefined;

function stubApi(calls: Call[], handler: Handler) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const url = new URL(request.url);
      const raw = request.method === "GET" ? null : await request.clone().text();
      const body = raw ? (JSON.parse(raw) as unknown) : null;
      calls.push({ method: request.method, path: url.pathname, body });
      if (url.pathname === "/api/v1/auth/me") return Response.json(me);
      return handler(url.pathname, request.method, body) ?? Response.json([]);
    }),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

const push = (status: string) => ({
  id: "p1",
  bulletin_id: "b1",
  bulletin_ref: "CERT-2026-0001",
  connector_id: "c1",
  connector_name: "Partenaire",
  connector_version: 1,
  rev_no: 2,
  is_test: false,
  origin: "user",
  requested_by: "u-eve",
  status,
  mode: "create",
  attempts: 1,
  next_attempt_at: null,
  remote_id: status === "succeeded" ? "ADV-1" : null,
  response_status: status === "succeeded" ? 201 : null,
  error: null,
  created_at: "2026-10-23T08:00:00Z",
  finished_at: null,
  attempt_log: [],
});

describe("publication screens", () => {
  it("creates a connector with its authentication, secret and mapping previewed", async () => {
    const calls: Call[] = [];
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/workspaces/cert/secrets")
        return Response.json([
          { id: "s1", name: "jeton-partenaire", purpose: "connector" },
          { id: "s2", name: "nvd", purpose: "source" },
        ]);
      if (path === "/api/v1/workspaces/cert/publish-mapping/preview")
        return Response.json({
          valid: true,
          errors: [],
          payload: { title: "Exemple" },
          request: null,
          paths: ["bulletin.title"],
          sample: true,
        });
      if (path === "/api/v1/workspaces/cert/connectors/publish" && method === "POST")
        return Response.json({ id: "c9", version: 1 }, { status: 201 });
      return undefined;
    });
    renderAt("/publish-connectors/new");
    fireEvent.change(await screen.findByLabelText("Nom"), { target: { value: "Partenaire" } });
    fireEvent.change(screen.getByLabelText("URL de base"), {
      target: { value: "https://api.partner.example" },
    });
    fireEvent.change(screen.getByLabelText("Chemin"), { target: { value: "/v2/advisories" } });
    // The default authentication (bearer) asks for its secret; only connector secrets.
    await screen.findAllByRole("option", { name: "jeton-partenaire" });
    expect(screen.queryByRole("option", { name: "nvd" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Clé ou jeton *"), { target: { value: "s1" } });
    expect(
      await screen.findByText(/"title": "Exemple"/, {}, { timeout: 3000 }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Créer le connecteur" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/connectors/publish"))).toBe(
        true,
      ),
    );
    const created = calls.find(
      (c) => c.method === "POST" && c.path.endsWith("/connectors/publish"),
    );
    expect(created?.body).toMatchObject({
      kind: "http_generic",
      name: "Partenaire",
      secret_refs: { credential: "s1" },
      config: {
        request: { base_url: "https://api.partner.example", path: "/v2/advisories" },
        auth: { type: "bearer", endpoint_url: null },
        body: { format: "json" },
      },
    });
  });

  it("pushes a validated bulletin after reading the exact request", async () => {
    const calls: Call[] = [];
    let polls = 0;
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/workspaces/cert/bulletins/b1")
        return Response.json({
          id: "b1",
          ref: "CERT-2026-0001",
          title: "RCE",
          status: "approved",
          severity: "critical",
          tlp: "GREEN",
          language: "fr",
          workspace_slug: "cert",
          own: true,
          author_id: "u-ana",
          current_rev_no: 2,
          published_rev_no: null,
          published_at: null,
          updated_at: "2026-10-23T08:00:00Z",
          version: 3,
          audience_type: "all_clients",
          audience_org_ids: [],
          template_id: "t1",
          template_name: "Générique",
          template_version_no: 1,
          template_spec: { fields: [] },
          review_required: false,
          submitted_by: null,
          reviewer_id: "u-eve",
          approved_at: "2026-10-23T08:00:00Z",
          withdrawn_reason: null,
          current: {
            rev_no: 2,
            created_by_type: "user",
            created_by: "u-ana",
            agent_run_id: null,
            change_note: "",
            content_hash: "h",
            created_at: "2026-10-23T08:00:00Z",
            fields: {},
            rendered_markdown: "# RCE",
            rendered_html: "<h1>RCE</h1>",
          },
          revisions: [],
          vulnerabilities: [],
          technologies: [],
          translation_of: null,
          translations: [],
        });
      if (path === "/api/v1/workspaces/cert/publish-targets")
        return Response.json([
          {
            id: "c1",
            name: "Partenaire",
            kind: "http_generic",
            scope: "workspace",
            enabled: true,
            health: "ok",
            body_format: "json",
          },
        ]);
      if (path === "/api/v1/workspaces/cert/publish-targets/c1/dry-run")
        return Response.json({
          method: "POST",
          url: "https://api.partner.example/v2/advisories",
          headers: { Authorization: "Bearer ••••••", "Content-Type": "application/json" },
          body: '{"title": "RCE"}',
          mode: "create",
        });
      if (path === "/api/v1/workspaces/cert/bulletins/b1/push" && method === "POST")
        return Response.json(push("queued"), { status: 202 });
      if (path === "/api/v1/workspaces/cert/publications/p1") {
        polls += 1;
        return Response.json(push(polls > 1 ? "succeeded" : "sending"));
      }
      return undefined;
    });
    renderAt("/bulletins/b1");
    fireEvent.click(await screen.findByRole("button", { name: "Pousser vers…" }));
    await screen.findByRole("option", { name: "Partenaire" });
    fireEvent.change(screen.getByLabelText("Connecteur"), { target: { value: "c1" } });
    expect(await screen.findByText(/Authorization: Bearer ••••••/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirmer l'envoi" }));
    expect(await screen.findByText("Réussi", {}, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText(/identifiant distant ADV-1/)).toBeInTheDocument();
    const sent = calls.find((c) => c.path.endsWith("/bulletins/b1/push"));
    expect(sent?.body).toEqual({ connector_id: "c1" });
    // Exports of the validated bulletin.
    const links = [...document.querySelectorAll("a[download]")].map((a) => a.getAttribute("href"));
    expect(links).toContain("/api/v1/workspaces/cert/bulletins/b1/export?format=csaf");
  });

  it("lets an administrator approve a private range with a note", async () => {
    const calls: Call[] = [];
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/admin/private-network-requests" && method === "GET")
        return Response.json([
          {
            id: "r1",
            connector_id: "c1",
            workspace_slug: "voc",
            connector_name: "Portail interne",
            hosts: ["portal.corp.example"],
            cidrs: ["10.20.0.0/16"],
            reason: "Diffusion interne",
            status: "pending",
            requested_by: "u-ana",
            requested_at: "2026-10-23T08:00:00Z",
            decided_by: null,
            decided_at: null,
            decision_note: "",
          },
        ]);
      if (path.endsWith("/decision")) return Response.json({});
      return undefined;
    });
    renderAt("/admin/private-network");
    expect(await screen.findByText("portal.corp.example")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approuver" }));
    fireEvent.change(await screen.findByLabelText("Note (facultative)"), {
      target: { value: "Vu avec le RSSI" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirmer" }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/decision"))).toBe(true));
    expect(calls.find((c) => c.path.endsWith("/decision"))?.body).toEqual({
      approve: true,
      note: "Vu avec le RSSI",
    });
  });
});
