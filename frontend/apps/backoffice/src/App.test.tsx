import { render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import { routes } from "./routes";

afterEach(() => vi.unstubAllGlobals());

const me = (permissions: string[]) => ({
  id: "u1",
  email: "ana@example.com",
  display_name: "Ana Lyste",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions,
  workspaces: [{ slug: "voc", name: "VOC", role: "analyst", permissions: [] }],
  client_org: null,
});

function stubMe(body: unknown, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string) =>
      new URL(typeof input === "string" ? input : input.url).pathname === "/api/v1/auth/me"
        ? Response.json(body, { status })
        : Response.json({ items: [], next_cursor: null }),
    ),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("back-office", () => {
  it("redirects anonymous visitors to the login page", async () => {
    stubMe({ detail: "not_authenticated" }, 401);
    renderAt("/");
    expect(await screen.findByRole("button", { name: "Se connecter" })).toBeInTheDocument();
  });

  it("shows admin navigation to platform admins only", async () => {
    stubMe(me(["iam.users.manage", "audit.read_global"]));
    renderAt("/");
    expect(await screen.findByRole("link", { name: "Utilisateurs" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Audit" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Clients" })).not.toBeInTheDocument();
  });

  it("refuses an admin page without the permission", async () => {
    stubMe(me([]));
    renderAt("/admin/users");
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Vous n'avez pas les droits nécessaires.",
      ),
    );
  });

  it("shows a generic page for unknown addresses", async () => {
    stubMe(me([]));
    renderAt("/nowhere");
    expect(await screen.findByText("Une erreur est survenue. Réessayez.")).toBeInTheDocument();
  });
});
