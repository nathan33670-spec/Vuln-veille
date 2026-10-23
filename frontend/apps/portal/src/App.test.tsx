import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import { routes } from "./routes";

afterEach(() => vi.unstubAllGlobals());

const me = (role: string, permissions: string[]) => ({
  id: "u1",
  email: "ref@acme.example.com",
  display_name: "Réf Acme",
  user_type: "client",
  locale: "fr",
  mfa_enabled: false,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions,
  workspaces: [],
  client_org: { id: "o1", name: "Acme", role },
});

const BULLETIN = {
  id: "b1",
  ref: "CERT-2026-0001",
  title: "RCE dans Exemple",
  severity: "critical",
  tlp: "AMBER",
  language: "fr",
  team: "CERT",
  cves: ["CVE-2026-0001"],
  technologies: [{ vendor: "exemple", product: "serveur", name: "Exemple Serveur" }],
  published_at: "2026-10-20T08:00:00Z",
  updated_at: "2026-10-22T08:00:00Z",
};

const ORG_USERS = {
  items: [
    {
      id: "u2",
      email: "col@acme.example.com",
      display_name: "Collègue",
      user_type: "client",
      status: "active",
      mfa_enabled: false,
      locked: false,
      last_login_at: null,
      created_at: "2026-10-20T00:00:00Z",
      role: "client_user",
    },
  ],
  next_cursor: null,
};

let requests: { method: string; path: string; search: string; body: string }[] = [];

function stub(body: unknown, status = 200, preferences = { email_bulletins: false }) {
  requests = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string) => {
      const request = typeof input === "string" ? new Request(input) : input;
      const url = new URL(request.url);
      requests.push({
        method: request.method,
        path: url.pathname,
        search: url.search,
        body: request.method === "GET" ? "" : await request.clone().text(),
      });
      switch (url.pathname) {
        case "/api/portal/v1/auth/me":
          return Response.json(body, { status });
        case "/api/portal/v1/branding":
          return Response.json({ issuer_name: "CERT Exemple", has_logo: true, version: 3 });
        case "/api/portal/v1/bulletins":
          return Response.json({ items: [BULLETIN], total: 1, page: 1, page_size: 20 });
        case "/api/portal/v1/bulletins/b1":
          return Response.json({
            ...BULLETIN,
            html: '<h1>RCE</h1><p>Contenu.</p><script>alert(1)</script><img src="x" onerror="alert(1)">',
            history: [
              { kind: "updated", at: "2026-10-22T08:00:00Z" },
              { kind: "published", at: "2026-10-20T08:00:00Z" },
            ],
          });
        case "/api/portal/v1/me/notifications":
          if (request.method === "PUT") return Response.json(JSON.parse(await request.text()));
          return Response.json(preferences);
        default:
          return Response.json(ORG_USERS);
      }
    }),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("portal", () => {
  it("redirects anonymous visitors to the login page", async () => {
    stub({ detail: "not_authenticated" }, 401);
    renderAt("/");
    expect(await screen.findByRole("button", { name: "Se connecter" })).toBeInTheDocument();
  });

  it("shows the organization page to client referents only", async () => {
    stub(me("client_user", ["portal.bulletins.read"]));
    renderAt("/");
    expect(await screen.findByRole("link", { name: "Bulletins" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Mon organisation" })).not.toBeInTheDocument();
  });

  it("lets a referent see the members of the organization", async () => {
    stub(me("client_admin", ["portal.bulletins.read", "portal.org_users.manage"]));
    renderAt("/organization");
    expect(await screen.findByText("col@acme.example.com")).toBeInTheDocument();
    expect(screen.getByLabelText("Rôle de Collègue")).toHaveValue("client_user");
  });

  it("lists the bulletins with the issuer's branding and passes the filters", async () => {
    stub(me("client_user", ["portal.bulletins.read"]));
    renderAt("/?q=exemple&severity=critical");
    expect(await screen.findByRole("link", { name: "RCE dans Exemple" })).toHaveAttribute(
      "href",
      "/bulletins/b1",
    );
    expect(screen.getByText("CERT Exemple")).toBeInTheDocument();
    expect(document.querySelector("img.vv-brand-logo")).toHaveAttribute(
      "src",
      "/api/portal/v1/branding/logo?v=3",
    );
    const list = requests.find((r) => r.path === "/api/portal/v1/bulletins");
    expect(list?.search).toContain("q=exemple");
    expect(list?.search).toContain("severity=critical");
    expect(screen.getByLabelText("Recherche")).toHaveValue("exemple");
  });

  it("shows a bulletin sanitized, with its history and exports", async () => {
    stub(me("client_user", ["portal.bulletins.read"]));
    renderAt("/bulletins/b1");
    expect(await screen.findByRole("heading", { name: "RCE" })).toBeInTheDocument();
    expect(document.querySelector("main script")).toBeNull();
    expect(document.querySelector("main [onerror]")).toBeNull();
    expect(screen.getByText("TLP:AMBER")).toBeInTheDocument();
    expect(screen.getByText(/Mise à jour —/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "PDF" })).toHaveAttribute(
      "href",
      "/api/portal/v1/bulletins/b1/export?format=pdf",
    );
    expect(screen.getByRole("button", { name: "Imprimer" })).toBeInTheDocument();
  });

  it("lets each user choose to receive bulletins by e-mail", async () => {
    stub(me("client_user", ["portal.bulletins.read"]));
    renderAt("/notifications");
    const box = await screen.findByLabelText("Recevoir les bulletins par e-mail");
    expect(box).not.toBeChecked();
    fireEvent.click(box);
    expect(await screen.findByText("Vous recevrez les bulletins par e-mail.")).toBeInTheDocument();
    expect(box).toBeChecked();
    const put = requests.find((r) => r.method === "PUT");
    expect(JSON.parse(put?.body ?? "{}")).toEqual({ email_bulletins: true });
  });

  it("refuses the organization page without the permission", async () => {
    stub(me("client_user", ["portal.bulletins.read"]));
    renderAt("/organization");
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Vous n'avez pas les droits nécessaires.",
      ),
    );
  });
});
