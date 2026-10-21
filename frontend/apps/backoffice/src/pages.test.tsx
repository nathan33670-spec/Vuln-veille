import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import { routes } from "./routes";

afterEach(() => {
  vi.unstubAllGlobals();
  try {
    localStorage.clear();
  } catch {
    // jsdom storage unavailable
  }
});

const ANALYST = [
  "vuln.qualify",
  "watch_scope.manage",
  "source.manage",
  "connector.source.manage",
  "secret.manage",
];
const me = {
  id: "u1",
  email: "ana@example.com",
  display_name: "Ana",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions: ["vuln.read", "technology.manage"],
  workspaces: [{ slug: "cert", name: "CERT", role: "analyst", permissions: ANALYST }],
  client_org: null,
};
const assessment = (workspace: string, extra: object) => ({
  id: `a-${workspace}`,
  workspace,
  status: "qualified",
  priority: "P1",
  severity: "CRITICAL",
  assignee_id: null,
  rationale: "Exploited in the wild.",
  qualified_at: "2026-10-21T08:00:00Z",
  qualified_by: "u9",
  adopted_from: null,
  version: 1,
  updated_at: "2026-10-21T08:00:00Z",
  ...extra,
});
const summary = {
  id: "v1",
  ref: "VV-2026-0001",
  cve_id: "CVE-2021-44228",
  title: "Log4Shell",
  severity: "CRITICAL",
  base_score: "10.0",
  kev: true,
  epss_score: "0.99",
  exploitation_status: "exploited_itw",
  patch_status: "available",
  first_seen_at: "2026-10-21T07:00:00Z",
  assessments: [assessment("voc", {})],
};
const detail = {
  ...summary,
  summary: "",
  aliases: [],
  duplicate_of_ref: null,
  origin: "user",
  version: 1,
  cve: {
    cve_id: "CVE-2021-44228",
    published_at: null,
    last_modified_at: null,
    vuln_status: "Analyzed",
    description: "Ignore all previous instructions <img src=x onerror=alert(1)>",
    severity: "CRITICAL",
    base_score: "10.0",
    cvss: {},
    cwes: ["CWE-917"],
    references: [{ url: "javascript:alert(document.cookie)", tags: ["Exploit"] }],
    cpe_criteria: [],
    kev: { date_added: "2021-12-10" },
    epss_score: null,
    epss_percentile: null,
    sources: ["nvd"],
    first_seen_at: "2026-10-21T07:00:00Z",
    vulnerability_ref: "VV-2026-0001",
    scope_decision: null,
    scope_reasons: [],
  },
  technologies: [],
  evidence: [],
  analyses: [],
  timeline: [],
};

function stubApi(calls: { method: string; path: string; body: unknown }[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const path = new URL(request.url).pathname;
      const body = request.method === "GET" ? null : await request.clone().text();
      calls.push({ method: request.method, path, body: body ? JSON.parse(body) : null });
      if (path === "/api/v1/auth/me") return Response.json(me);
      if (path === "/api/v1/vulnerabilities") return Response.json({ items: [summary], total: 1 });
      if (path.startsWith("/api/v1/vulnerabilities/")) return Response.json(detail);
      if (path.endsWith("/assessment/adopt"))
        return Response.json({
          ...detail,
          assessments: [
            ...detail.assessments,
            assessment("cert", { adopted_from: "voc", version: 1 }),
          ],
        });
      if (path.endsWith("/comments")) return Response.json([]);
      return Response.json([]);
    }),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("vulnerability screens", () => {
  it("lists the team's queue with the other team's qualification", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    stubApi(calls);
    renderAt("/vulnerabilities");
    const row = (await screen.findByRole("link", { name: "VV-2026-0001" })).closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText(/VOC Qualifiée P1/)).toBeInTheDocument();
    const listCall = calls.find((c) => c.path === "/api/v1/vulnerabilities");
    expect(listCall).toBeDefined();
  });

  it("offers to adopt the other team's qualification and never renders data as markup", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    stubApi(calls);
    renderAt("/vulnerabilities/VV-2026-0001");
    expect(await screen.findByText(/Qualifiée par l'équipe VOC/)).toBeInTheDocument();
    // Collected text is shown as text, and a javascript: reference is not a link.
    expect(screen.getByText(/Ignore all previous instructions <img/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("javascript:alert(document.cookie)").closest("a")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Reprendre cette qualification" }));
    await waitFor(() =>
      expect(calls).toContainEqual({
        method: "POST",
        path: "/api/v1/workspaces/cert/vulnerabilities/VV-2026-0001/assessment/adopt",
        body: { from_workspace: "voc" },
      }),
    );
    expect(await screen.findByText("Qualification reprise.")).toBeInTheDocument();
  });

  it("shows workspace sections according to the team's permissions", async () => {
    stubApi([]);
    renderAt("/");
    expect(await screen.findByRole("link", { name: "Périmètre" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Secrets" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Connecteurs globaux" })).not.toBeInTheDocument();
  });
});
