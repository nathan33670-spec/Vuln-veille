import { fireEvent, render, screen } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import { routes } from "./routes";

afterEach(() => {
  vi.unstubAllGlobals();
});

const me = (permissions: string[]) => ({
  id: "u-ana",
  email: "ana@example.com",
  display_name: "Ana",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions,
  workspaces: [],
  client_org: null,
});

type Call = { method: string; path: string; body: unknown };

function stubApi(calls: Call[], permissions: string[]) {
  let branding = { issuer_name: "", has_logo: false, version: 1 };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const url = new URL(request.url);
      const raw = request.method === "GET" ? null : await request.clone().text();
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
      calls.push({ method: request.method, path: url.pathname, body });
      if (url.pathname === "/api/v1/auth/me") return Response.json(me(permissions));
      if (url.pathname === "/api/v1/admin/branding") {
        if (request.method === "PUT" && body) {
          branding = { ...branding, issuer_name: String(body.issuer_name), version: 2 };
        }
        return Response.json(branding);
      }
      return Response.json([]);
    }),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("platform branding", () => {
  it("lets a platform administrator name the issuer", async () => {
    const calls: Call[] = [];
    stubApi(calls, ["platform.branding.manage"]);
    renderAt("/admin/branding");
    const field = await screen.findByLabelText("Nom de l'émetteur");
    expect(screen.getByText("Aucun logo.")).toBeInTheDocument();
    expect(screen.getByLabelText("Choisir un logo (PNG ou JPEG)")).toHaveAttribute(
      "accept",
      "image/png,image/jpeg",
    );
    fireEvent.change(field, { target: { value: "CERT Exemple" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText("Nom de l'émetteur enregistré.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
      issuer_name: "CERT Exemple",
      version: 1,
    });
  });

  it("is hidden without the permission", async () => {
    stubApi([], []);
    renderAt("/admin/branding");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Vous n'avez pas les droits nécessaires.",
    );
    expect(screen.queryByRole("link", { name: "Charte du portail" })).not.toBeInTheDocument();
  });
});
