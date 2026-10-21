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
  id: "u1",
  email: "ana@example.com",
  display_name: "Ana",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions: ["vuln.read"],
  workspaces: [
    {
      slug: "voc",
      name: "VOC",
      role: "analyst",
      permissions: ["workflow.read", "workflow.edit", "workflow.run"],
    },
  ],
  client_org: null,
};
const graph = {
  schema_version: 1,
  nodes: [
    { id: "start", type: "trigger.manual", name: "Départ", params: {} },
    { id: "limit", type: "transform.limit", name: "Limite", params: { count: 5 } },
  ],
  edges: [{ id: "e1", from: { node: "start", port: "out" }, to: { node: "limit", port: "in" } }],
};
const workflow = {
  id: "w1",
  name: "Nouvelle CVE NVD",
  description: "",
  status: "active",
  tags: [],
  seed_key: null,
  active_version_no: 1,
  latest_version_no: 1,
  version: 2,
  updated_at: "2026-10-21T08:00:00Z",
  last_run: null,
  versions: [
    {
      id: "v1",
      version_no: 1,
      comment: "",
      graph_hash: "h",
      created_by: null,
      created_at: "2026-10-21T08:00:00Z",
    },
  ],
  latest_graph: graph,
  triggers: [],
};
const run = {
  id: "r1",
  workflow_id: "w1",
  version_no: 1,
  trigger_type: "manual",
  status: "waiting_approval",
  queued_at: "2026-10-21T08:00:00Z",
  started_at: "2026-10-21T08:00:01Z",
  finished_at: null,
  error: null,
  stats: {},
  trigger_node_id: "start",
  triggered_by: "u1",
  trigger_payload: {},
  cancel_requested: false,
  deadline_at: null,
  node_runs: [
    {
      node_id: "feed",
      attempt: 1,
      status: "succeeded",
      queue: "collect",
      scheduled_at: "2026-10-21T08:00:01Z",
      started_at: "2026-10-21T08:00:01Z",
      finished_at: "2026-10-21T08:00:03Z",
      input_count: 1,
      output_count: 1,
      output_truncated: false,
      error: null,
      logs: [],
      metrics: {},
    },
  ],
  approvals: [
    {
      node_id: "approve",
      requested_at: "2026-10-21T08:00:03Z",
      decision: null,
      decided_by: null,
      decided_at: null,
      comment: "",
    },
  ],
};

type Call = { method: string; path: string; body: unknown };

function stubApi(calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const path = new URL(request.url).pathname;
      const body = request.method === "GET" ? null : await request.clone().text();
      calls.push({ method: request.method, path, body: body ? JSON.parse(body) : null });
      if (path === "/api/v1/auth/me") return Response.json(me);
      if (path === "/api/v1/workspaces/voc/workflows/w1/versions")
        return Response.json(
          {
            detail: "invalid_graph",
            errors: [{ path: "nodes.1.params.count", code: "greater_than_equal" }],
          },
          { status: 422 },
        );
      if (path === "/api/v1/workspaces/voc/workflows/w1") return Response.json(workflow);
      if (path === "/api/v1/workspaces/voc/runs/r1/nodes/feed")
        return Response.json({
          ...run.node_runs[0],
          output: { out: [{ json: { title: "<img src=x onerror=alert(1)>" }, meta: {} }] },
        });
      if (path === "/api/v1/workspaces/voc/runs/r1") return Response.json(run);
      if (path.endsWith("/approvals/approve")) return Response.json(run);
      return Response.json([]);
    }),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("workflow screens", () => {
  it("shows the graph and the located validation errors of a new version", async () => {
    const calls: Call[] = [];
    stubApi(calls);
    renderAt("/workflows/w1");
    expect(await screen.findByText("Limite")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Modifier (JSON)" }));
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer une nouvelle version" }));
    expect(await screen.findByText("nodes.1.params.count")).toBeInTheDocument();
    expect(screen.getByText(/Le graphe contient des erreurs/)).toBeInTheDocument();
    const saved = calls.find((c) => c.path.endsWith("/versions"));
    expect(saved?.body).toMatchObject({ base_version_no: 1, graph });
  });

  it("decides a pending approval and shows node output as plain text", async () => {
    const calls: Call[] = [];
    stubApi(calls);
    renderAt("/runs/r1");
    expect(await screen.findByText("Validation attendue : approve")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "feed" }));
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Valider" }));
    await waitFor(() =>
      expect(calls).toContainEqual({
        method: "POST",
        path: "/api/v1/workspaces/voc/runs/r1/approvals/approve",
        body: { decision: "approved", comment: "" },
      }),
    );
  });
});
