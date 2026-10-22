import { EditorView } from "@codemirror/view";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import {
  connectionError,
  type Graph,
  layout,
  locateErrors,
  newNodeId,
  type NodeType,
  parseGraph,
} from "./pages/workflows/editor/model";
import { explainCron } from "./pages/workflows/editor/cron";
import { comparableJson, diffGraphs, lineDiff } from "./pages/workflows/editor/diff";
import { fieldsOf } from "./pages/workflows/editor/schema";
import { readWorkflowFile } from "./pages/workflows/workflowFile";
import { routes } from "./routes";

// React Flow measures its nodes: jsdom has no layout engine.
beforeAll(() => {
  class ResizeObserverStub {
    constructor(private readonly callback: ResizeObserverCallback) {}
    observe(target: Element) {
      const contentRect = { width: 800, height: 600 } as DOMRectReadOnly;
      this.callback(
        [{ target, contentRect } as ResizeObserverEntry],
        this as unknown as ResizeObserver,
      );
    }
    unobserve() {}
    disconnect() {}
  }
  class DOMMatrixStub {
    m22 = 1;
  }
  Object.assign(globalThis, {
    ResizeObserver: ResizeObserverStub,
    DOMMatrixReadOnly: DOMMatrixStub,
  });
  // CodeMirror measures text ranges.
  const rects = () => Object.assign([], { item: () => null }) as unknown as DOMRectList;
  Range.prototype.getClientRects = rects;
  Range.prototype.getBoundingClientRect = () => new DOMRect();
  Object.defineProperties(HTMLElement.prototype, {
    offsetHeight: { configurable: true, get: () => 60 },
    offsetWidth: { configurable: true, get: () => 180 },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const expr = {
  additionalProperties: false,
  properties: { $expr: { type: "string", maxLength: 2000 } },
  required: ["$expr"],
  type: "object",
};
const tpl = {
  additionalProperties: false,
  properties: { $tpl: { type: "string" } },
  required: ["$tpl"],
  type: "object",
};

function nodeType(type: string, overrides: Partial<NodeType> = {}): NodeType {
  return {
    type,
    version: 1,
    label: type,
    category: type.split(".")[0] ?? "transform",
    queue: "default",
    inputs: type.startsWith("trigger.") ? [] : ["in"],
    outputs: ["out"],
    params_schema: { properties: {}, type: "object" },
    required_permissions: [],
    uses_egress: false,
    requires_approval_upstream: false,
    trigger_type: null,
    reference_fields: {},
    ...overrides,
  };
}

const TYPES: NodeType[] = [
  nodeType("trigger.manual", { label: "Lancement manuel", trigger_type: "manual" }),
  nodeType("trigger.schedule", {
    label: "Planification",
    trigger_type: "schedule",
    params_schema: {
      properties: { cron: { type: "string", title: "Cron", maxLength: 100 } },
      required: ["cron"],
      type: "object",
    },
  }),
  nodeType("transform.limit", {
    label: "Limiter",
    params_schema: {
      properties: { count: { type: "integer", minimum: 1, maximum: 5000, title: "Count" } },
      required: ["count"],
      type: "object",
    },
  }),
  nodeType("transform.filter", {
    label: "Filtrer",
    params_schema: {
      $defs: { Expr: expr },
      properties: { condition: { $ref: "#/$defs/Expr" } },
      required: ["condition"],
      type: "object",
    },
  }),
  nodeType("vuln.scope_match", { label: "Périmètre", outputs: ["in_scope", "out_of_scope"] }),
  nodeType("source.x", {
    label: "X",
    category: "source",
    params_schema: {
      properties: {
        connector_id: { format: "uuid", type: "string", title: "Connector Id" },
        only_new: { default: false, type: "boolean", title: "Only New" },
      },
      required: ["connector_id"],
      type: "object",
    },
    reference_fields: {
      connector_id: { kind: "connector", family: "source", connector_kinds: ["x_reader"] },
    },
  }),
  nodeType("publish.api", { label: "Publier", required_permissions: ["connector.publish.push"] }),
  nodeType("ai.summarize", {
    label: "Résumer (IA)",
    params_schema: {
      properties: { max_items: { type: "integer", default: 10, title: "Max Items" } },
      type: "object",
    },
  }),
];
const typeMap = new Map(TYPES.map((t) => [t.type, t]));

describe("graph model", () => {
  const graph: Graph = {
    schema_version: 1,
    nodes: [
      { id: "start", type: "trigger.manual", params: {} },
      { id: "scope", type: "vuln.scope_match", params: {} },
      { id: "limit", type: "transform.limit", params: { count: 5 } },
    ],
    edges: [
      { id: "e1", from: { node: "start", port: "out" }, to: { node: "scope", port: "in" } },
      { id: "e2", from: { node: "scope", port: "in_scope" }, to: { node: "limit", port: "in" } },
    ],
  };
  const c = (source: string, sourceHandle: string, target: string, targetHandle: string) => ({
    source,
    sourceHandle,
    target,
    targetHandle,
  });

  it("validates connections by port, and refuses cycles", () => {
    expect(connectionError(graph, typeMap, c("scope", "out_of_scope", "limit", "in"))).toBeNull();
    expect(connectionError(graph, typeMap, c("scope", "in_scope", "limit", "in"))).toBe(
      "duplicate",
    );
    expect(connectionError(graph, typeMap, c("scope", "out", "limit", "in"))).toBe("unknown_port");
    expect(connectionError(graph, typeMap, c("limit", "out", "start", "in"))).toBe("unknown_port");
    expect(connectionError(graph, typeMap, c("limit", "out", "scope", "in"))).toBe("cycle");
    expect(connectionError(graph, typeMap, c("limit", "out", "limit", "in"))).toBe("self");
  });

  it("lays out delivered graphs by depth, and names nodes after their type", () => {
    const placed = layout(graph);
    expect(placed.nodes.map((n) => n.position?.x)).toEqual([0, 280, 560]);
    expect(newNodeId("transform.limit", ["limit", "limit_2"])).toBe("limit_3");
    expect(newNodeId("source.x", [])).toBe("x");
  });

  it("locates server errors on their node and field", () => {
    const { byNode, global } = locateErrors(
      [
        { path: "nodes.2.params.count", code: "missing" },
        { path: "edges.0", code: "unknown_port" },
        { path: "", code: "no_trigger" },
      ],
      graph,
    );
    expect(byNode.get("limit")).toEqual([{ field: "count", code: "missing" }]);
    expect(byNode.get("scope")).toEqual([{ field: null, code: "unknown_port" }]);
    expect(global).toEqual([{ path: "", code: "no_trigger" }]);
  });

  it("reads untrusted graphs defensively", () => {
    const parsed = parseGraph({ nodes: [{ id: 3, params: "x" }, null], edges: "no" });
    expect(parsed.nodes[0]).toEqual({ id: "3", type: "", params: {} });
    expect(parsed.edges).toEqual([]);
  });

  it("derives form fields from the JSON Schema", () => {
    const fields = fieldsOf(
      {
        $defs: { Expr: expr, Tpl: tpl },
        properties: {
          run_if: { anyOf: [{ $ref: "#/$defs/Expr" }, { type: "null" }], default: null },
          subject: { $ref: "#/$defs/Tpl" },
          preset: { anyOf: [{ enum: ["triage", "poc_hunter"], type: "string" }, { type: "null" }] },
          agent_id: { anyOf: [{ format: "uuid", type: "string" }, { type: "null" }] },
          query: { type: "object", additionalProperties: { type: "string" } },
          change_types: { type: "array", items: { enum: ["kev_added", "rejected"] } },
        },
        type: "object",
      },
      { agent_id: { kind: "agent", family: null, connector_kinds: [] } },
    );
    expect(fields.map((f) => [f.name, f.kind, f.nullable])).toEqual([
      ["run_if", "expr", true],
      ["subject", "tpl", false],
      ["preset", "enum", true],
      ["agent_id", "reference", true],
      ["query", "json", false],
      ["change_types", "multi", false],
    ]);
  });
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
      permissions: ["workflow.read", "workflow.edit", "connector.source.manage"],
    },
  ],
  client_org: null,
};
const hostile = "<img src=x onerror=alert(1)>";
const latest = {
  schema_version: 1,
  nodes: [
    { id: "start", type: "trigger.manual", name: hostile, params: {} },
    { id: "limit", type: "transform.limit", params: { count: 5 } },
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
  versions: [],
  latest_graph: latest,
  triggers: [],
};
const connector = (id: string, kind: string, name: string) => ({
  id,
  kind,
  name,
  family: "source",
  enabled: true,
  config: {},
  secret_refs: {},
  egress_domains: [],
  allow_private_network: false,
  quotas: {},
  health: "ok",
  consecutive_failures: 0,
  last_check_at: null,
  last_error: null,
  last_success_at: null,
  created_at: "2026-10-21T08:00:00Z",
  updated_at: "2026-10-21T08:00:00Z",
  version: 1,
});

type Call = { method: string; path: string; body: unknown };

function stubApi(calls: Call[], options: { draft?: unknown; publish?: number } = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const path = new URL(request.url).pathname;
      const text = request.method === "GET" ? "" : await request.clone().text();
      const body = text ? JSON.parse(text) : null;
      calls.push({ method: request.method, path, body });
      const base = "/api/v1/workspaces/voc/workflows/w1";
      if (path === "/api/v1/auth/me") return Response.json(me);
      if (path === "/api/v1/node-types") return Response.json(TYPES);
      if (path === base) return Response.json(workflow);
      if (path === `${base}/draft` && request.method === "GET") {
        return options.draft
          ? Response.json(options.draft)
          : Response.json({ detail: "not_found" }, { status: 404 });
      }
      if (path === `${base}/draft` && request.method === "PUT") {
        const nodes = (body.graph.nodes ?? []) as { type: string; params: object }[];
        const index = nodes.findIndex(
          (n) => n.type === "transform.filter" && !("condition" in n.params),
        );
        return Response.json({
          graph: body.graph,
          base_version_no: body.base_version_no,
          latest_version_no: 1,
          stale: false,
          updated_by: "u1",
          updated_at: "2026-10-22T09:00:00Z",
          errors: index >= 0 ? [{ path: `nodes.${index}.params.condition`, code: "missing" }] : [],
        });
      }
      if (path === `${base}/draft` && request.method === "DELETE") {
        return new Response(null, { status: 204 });
      }
      if (path === `${base}/versions` && request.method === "POST") {
        if (options.publish === 409) {
          return Response.json({ detail: "version_conflict" }, { status: 409 });
        }
        return Response.json(
          {
            id: "v2",
            version_no: 2,
            comment: body.comment,
            graph_hash: "h",
            created_by: "u1",
            created_at: "2026-10-22T09:00:00Z",
          },
          { status: 201 },
        );
      }
      if (path === "/api/v1/workspaces/voc/connectors/source") {
        return Response.json([
          connector("c1", "x_reader", "Lecteur X"),
          connector("c2", "rss", "Flux RSS"),
        ]);
      }
      return Response.json([]);
    }),
  );
}

function renderEditor() {
  render(<App router={createMemoryRouter(routes, { initialEntries: ["/workflows/w1/edit"] })} />);
}

/** The CodeMirror view of an expression field (mounted in a shadow root). */
function codeView(label: string): EditorView {
  const host = screen.getByTestId(`code-${label}`);
  const dom = host.shadowRoot?.querySelector(".cm-editor");
  const view = dom ? EditorView.findFromDOM(dom as HTMLElement) : null;
  if (!view) throw new Error(`no code field ${label}`);
  return view;
}

function typeCode(label: string, text: string) {
  const view = codeView(label);
  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text } });
}

const lastDraft = (calls: Call[]) =>
  calls.filter((c) => c.method === "PUT" && c.path.endsWith("/draft")).at(-1)?.body as
    { graph: Graph; base_version_no: number } | undefined;

describe("workflow editor", () => {
  it("adds a node from the palette, saves the draft and shows its errors", async () => {
    const calls: Call[] = [];
    stubApi(calls);
    renderEditor();
    const start = await screen.findByTestId("node-start");
    // Analyst-typed and collected texts stay inert.
    expect(within(start).getByText(hostile)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    // A node needing a missing permission cannot be added.
    expect(screen.getByRole("button", { name: "Publier" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Filtrer" }));
    expect(await screen.findByTestId("node-filter")).toBeInTheDocument();
    await waitFor(() => expect(lastDraft(calls)).toBeDefined(), { timeout: 4000 });
    expect(lastDraft(calls)?.base_version_no).toBe(1);
    expect(lastDraft(calls)?.graph.nodes.map((n) => n.id)).toEqual(["start", "limit", "filter"]);
    // The server's validation lands on the node and on its field.
    expect(
      await within(screen.getByTestId("node-filter")).findByText("1 erreur", {}, { timeout: 4000 }),
    ).toBeVisible();
    expect(screen.getByText("Champ obligatoire.")).toBeInTheDocument();

    typeCode("Condition (JMESPath) *", "json.score >= `7`");
    await waitFor(
      () =>
        expect(lastDraft(calls)?.graph.nodes[2]?.params).toEqual({
          condition: { $expr: "json.score >= `7`" },
        }),
      { timeout: 4000 },
    );
    await waitFor(() => expect(screen.queryByText("1 erreur")).toBeNull(), { timeout: 4000 });

    // One undo step per field: the node goes back to its empty condition, then disappears.
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    expect(codeView("Condition (JMESPath) *").state.doc.toString()).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    await waitFor(() => expect(screen.queryByTestId("node-filter")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Rétablir" }));
    expect(await screen.findByTestId("node-filter")).toBeInTheDocument();
  });

  it("offers the workspace's connectors of the right kind", async () => {
    stubApi([]);
    renderEditor();
    await screen.findByTestId("node-start");
    fireEvent.click(screen.getByRole("button", { name: "X" }));
    const select = await screen.findByLabelText("Connecteur");
    const options = within(select)
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(options).toEqual(["—", "Lecteur X (x_reader)"]);
  });

  it("publishes a version from its base, then drops the draft", async () => {
    const calls: Call[] = [];
    stubApi(calls);
    renderEditor();
    await screen.findByTestId("node-start");
    fireEvent.click(screen.getByRole("button", { name: "Publier une version" }));
    fireEvent.change(await screen.findByLabelText("Commentaire"), {
      target: { value: "Filtre ajouté" },
    });
    fireEvent.submit(screen.getByLabelText("Commentaire").closest("form") as HTMLFormElement);
    expect(await screen.findByText(/Version 2 enregistrée/)).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.path.endsWith("/versions"));
    expect(post?.body).toMatchObject({ comment: "Filtre ajouté", base_version_no: 1 });
    expect((post?.body as { graph: Graph }).graph.nodes[0]?.position).toEqual({ x: 0, y: 0 });
    expect(calls.some((c) => c.method === "DELETE" && c.path.endsWith("/draft"))).toBe(true);
  });

  it("detects a concurrent publication instead of overwriting it", async () => {
    const calls: Call[] = [];
    stubApi(calls, { publish: 409 });
    renderEditor();
    await screen.findByTestId("node-start");
    fireEvent.click(screen.getByRole("button", { name: "Publier une version" }));
    fireEvent.submit(
      (await screen.findByLabelText("Commentaire")).closest("form") as HTMLFormElement,
    );
    expect(await screen.findByText(/Une autre version a été publiée/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Garder mes modifications/ })).toBeInTheDocument();
  });

  it("resumes a stale draft with a warning", async () => {
    stubApi([], {
      draft: {
        graph: latest,
        base_version_no: 1,
        latest_version_no: 3,
        stale: true,
        updated_by: "u2",
        updated_at: "2026-10-22T08:00:00Z",
        errors: [],
      },
    });
    renderEditor();
    expect(await screen.findByText(/part de la v1, mais la v3 a été publiée/)).toBeInTheDocument();
  });
});

const nodeRun = (nodeId: string, status: string, extra: Record<string, unknown> = {}) => ({
  node_id: nodeId,
  attempt: 1,
  status,
  queue: "default",
  scheduled_at: "2026-10-22T09:00:00Z",
  started_at: "2026-10-22T09:00:01Z",
  finished_at: status === "succeeded" ? "2026-10-22T09:00:03Z" : null,
  input_count: 1,
  output_count: 1,
  output_truncated: false,
  error: null,
  logs: [],
  metrics: {},
  ai_calls: 0,
  ai_cost_usd: null,
  ...extra,
});

const testGraph = {
  schema_version: 1,
  nodes: [
    { id: "start", type: "trigger.manual", params: {} },
    { id: "high", type: "transform.filter", params: { condition: { $expr: "json.score >= `7`" } } },
    { id: "summary", type: "ai.summarize", params: { max_items: 2 } },
  ],
  edges: [
    { id: "e1", from: { node: "start", port: "out" }, to: { node: "high", port: "in" } },
    { id: "e2", from: { node: "high", port: "out" }, to: { node: "summary", port: "in" } },
  ],
};
const event = {
  cve_id: "CVE-2026-1234",
  change_types: ["published"],
  source: "nvd",
  severity: "CRITICAL",
  base_score: 9.8,
};

function stubTestApi(calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const path = new URL(request.url).pathname;
      const text = request.method === "GET" ? "" : await request.clone().text();
      const body = text ? JSON.parse(text) : null;
      calls.push({ method: request.method, path, body });
      const ws = "/api/v1/workspaces/voc";
      const base = `${ws}/workflows/w1`;
      if (path === "/api/v1/auth/me") return Response.json(me);
      if (path === "/api/v1/node-types") return Response.json(TYPES);
      if (path === base) return Response.json({ ...workflow, latest_graph: testGraph });
      if (path === `${base}/draft`) return Response.json({ detail: "no_draft" }, { status: 404 });
      if (path === `${ws}/workflow-samples/cve/CVE-2026-1234`) {
        return Response.json({ event, summary: { ...event, description: "RCE" } });
      }
      if (path === `${ws}/workflows/preview-expression`) {
        return Response.json({ value: body.item.json.base_score >= 7, error: null });
      }
      if (path === `${base}/test-node`) {
        return Response.json({ run_id: `t-${body.node_id}`, created: true }, { status: 202 });
      }
      if (path === `${ws}/runs/t-high`) {
        return Response.json({
          status: "succeeded",
          error: null,
          node_runs: [nodeRun("high", "succeeded")],
        });
      }
      if (path === `${ws}/runs/t-high/nodes/high`) {
        return Response.json({
          ...nodeRun("high", "succeeded"),
          output: { out: [{ json: event }] },
        });
      }
      if (path === `${base}/nodes/high/outputs`) {
        return Response.json([
          {
            run_id: "t-high",
            mode: "test",
            status: "succeeded",
            finished_at: "2026-10-22T09:00:03Z",
            output_count: 1,
            version_no: null,
          },
        ]);
      }
      if (path === `${ws}/ai-budget`) {
        return Response.json({
          monthly_limit_usd: "10.00",
          hard_stop: true,
          period: "2026-10-01",
          spent_usd: "2.500000",
          percent: 25,
          exhausted: false,
          alerts_sent: [],
          history: [],
        });
      }
      return Response.json([]);
    }),
  );
}

async function selectNode(id: string) {
  fireEvent.click(await screen.findByTestId(`node-${id}`));
}

describe("node test and expressions", () => {
  it("pins a real CVE, tests a node alone and previews its expression", async () => {
    const calls: Call[] = [];
    stubTestApi(calls);
    renderEditor();
    await selectNode("high");
    fireEvent.click(await screen.findByRole("tab", { name: "Tester" }));
    fireEvent.change(screen.getByLabelText("CVE du catalogue"), {
      target: { value: "CVE-2026-1234" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Épingler cette CVE" }));
    expect(await screen.findByText("1 élément épinglé")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Tester ce nœud" }));
    await waitFor(() => expect(screen.getAllByText("Réussi").length).toBeGreaterThan(0));
    const post = calls.find((c) => c.path.endsWith("/test-node"));
    expect(post?.body).toMatchObject({ node_id: "high", inputs: { in: [{ json: event }] } });
    expect((post?.body as { graph: Graph }).graph.nodes.map((n) => n.id)).toEqual([
      "start",
      "high",
      "summary",
    ]);
    // The output, shown as data; the canvas node carries the test's status.
    expect(await screen.findByText("Port « out » : 1 élément(s)")).toBeInTheDocument();
    expect(within(screen.getByTestId("node-high")).getByText("Réussi")).toBeInTheDocument();

    // The pinned CVE is the sample of the expression preview, evaluated by the server.
    fireEvent.click(screen.getByRole("tab", { name: "Paramètres du nœud" }));
    typeCode("Condition (JMESPath) *", "json.base_score >= `7`");
    expect(await screen.findByText("true", {}, { timeout: 3000 })).toBeInTheDocument();
    const preview = calls.find((c) => c.path.endsWith("/preview-expression"));
    expect(preview?.body).toEqual({ expr: "json.base_score >= `7`", item: { json: event } });
  });

  it("asks before a billed AI test, and pins the upstream node's last output", async () => {
    const calls: Call[] = [];
    stubTestApi(calls);
    renderEditor();
    await selectNode("summary");
    fireEvent.click(await screen.findByRole("tab", { name: "Tester" }));
    fireEvent.click(await screen.findByRole("button", { name: "Épingler cette sortie" }));
    expect(await screen.findByText("1 élément épinglé")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Tester ce nœud" }));
    expect(await screen.findByText(/2,5000 \$|2\.5000 \$/)).toBeInTheDocument();
    expect(screen.getByText(/1 appel\(s\) au plus/)).toBeInTheDocument();
    expect(calls.some((c) => c.path.endsWith("/test-node"))).toBe(false); // not before consent
    // jsdom does not open native dialogs: the button is found by its text.
    fireEvent.click(screen.getByText("Lancer le test (facturé)"));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/test-node"))).toBe(true));
    const post = calls.find((c) => c.path.endsWith("/test-node"));
    expect(post?.body).toMatchObject({ node_id: "summary", inputs: { in: [{ json: event }] } });
  });
});

describe("run view", () => {
  it("shows the run on its graph, updated live, with each node's AI cost", async () => {
    let polls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: Request | string, init?: RequestInit) => {
        const request = typeof input === "string" ? new Request(input, init) : input;
        const path = new URL(request.url).pathname;
        const ws = "/api/v1/workspaces/voc";
        if (path === "/api/v1/auth/me") return Response.json(me);
        if (path === "/api/v1/node-types") return Response.json(TYPES);
        if (path === `${ws}/workflows/w1/versions/1`) {
          return Response.json({ version_no: 1, graph: testGraph, comment: "" });
        }
        if (path === `${ws}/runs/r1`) {
          polls += 1;
          const done = polls > 2; // the page, then a first poll, see it running
          return Response.json({
            id: "r1",
            workflow_id: "w1",
            version_no: 1,
            trigger_type: "manual",
            status: done ? "succeeded" : "running",
            queued_at: "2026-10-22T09:00:00Z",
            started_at: "2026-10-22T09:00:01Z",
            finished_at: done ? "2026-10-22T09:00:09Z" : null,
            error: null,
            stats: {},
            mode: "normal",
            test_node_id: null,
            trigger_node_id: "start",
            triggered_by: "u1",
            trigger_payload: { cve_id: "CVE-2026-1234" },
            cancel_requested: false,
            deadline_at: null,
            approvals: [],
            node_runs: [
              nodeRun("start", "succeeded"),
              nodeRun("high", "succeeded"),
              nodeRun("summary", done ? "succeeded" : "running", {
                ai_calls: done ? 2 : 0,
                ai_cost_usd: done ? "0.024000" : null,
              }),
            ],
          });
        }
        if (path === `${ws}/runs/r1/nodes/summary`) {
          return Response.json({
            ...nodeRun("summary", "succeeded", { ai_calls: 2, ai_cost_usd: "0.024000" }),
            output: { out: [{ json: { summary: hostile } }] },
          });
        }
        return Response.json([]);
      }),
    );
    render(<App router={createMemoryRouter(routes, { initialEntries: ["/runs/r1"] })} />);
    const summary = await screen.findByTestId("node-summary");
    expect(within(summary).getByText("En cours")).toBeInTheDocument();
    await waitFor(() => expect(within(summary).getByText("Réussi")).toBeInTheDocument(), {
      timeout: 4000,
    });
    expect(within(summary).getByText(/IA 0\.0240 \$/)).toBeInTheDocument();
    fireEvent.click(summary);
    expect(await screen.findByText("2 appels, 0.0240 $ estimés")).toBeInTheDocument();
    expect(screen.getByText(/onerror=alert\(1\)/)).toBeInTheDocument(); // output, as text
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("versions", () => {
  const v1: Graph = {
    schema_version: 1,
    nodes: [
      { id: "start", type: "trigger.manual", params: {}, position: { x: 0, y: 0 } },
      {
        id: "high",
        type: "transform.filter",
        params: { condition: { $expr: "json.score >= `7`" } },
        position: { x: 280, y: 0 },
      },
      { id: "old", type: "transform.limit", params: { count: 5 }, position: { x: 560, y: 0 } },
    ],
    edges: [
      { id: "e1", from: { node: "start", port: "out" }, to: { node: "high", port: "in" } },
      { id: "e2", from: { node: "high", port: "out" }, to: { node: "old", port: "in" } },
    ],
  };
  const v2: Graph = {
    schema_version: 1,
    nodes: [
      { id: "start", type: "trigger.manual", params: {}, position: { x: 40, y: 40 } }, // moved
      {
        id: "high",
        type: "transform.filter",
        params: { condition: { $expr: "json.score >= `9`" } },
        position: { x: 280, y: 0 },
      },
      { id: "summary", type: "ai.summarize", params: {}, position: { x: 560, y: 0 } },
    ],
    edges: [
      { id: "e1", from: { node: "start", port: "out" }, to: { node: "high", port: "in" } },
      { id: "e3", from: { node: "high", port: "out" }, to: { node: "summary", port: "in" } },
    ],
  };

  it("diffs two graphs, positions aside", () => {
    const diff = diffGraphs(v1, v2);
    expect(Object.fromEntries(diff.nodes)).toEqual({
      start: "same",
      high: "modified",
      summary: "added",
      old: "removed",
    });
    expect(diff.fields.get("high")).toEqual([
      {
        path: "params.condition",
        before: { $expr: "json.score >= `7`" },
        after: { $expr: "json.score >= `9`" },
      },
    ]);
    expect(diff.edges.added.map((e) => e.id)).toEqual(["e3"]);
    expect(diff.edges.removed.map((e) => e.id)).toEqual(["e2"]);
    expect(comparableJson(v1)).not.toContain("position");
    expect(lineDiff("a\nb\nc", "a\nc\nd")).toEqual([
      { op: " ", text: "a" },
      { op: "-", text: "b" },
      { op: " ", text: "c" },
      { op: "+", text: "d" },
    ]);
  });

  it("explains a cron in French and reads workflow files", async () => {
    expect(explainCron("30 8 * * 1-5")).toBe("À 08:30, de lundi à vendredi");
    expect(explainCron("not a cron")).toBeNull();
    const file = (content: string, name = "w.json") => new File([content], name);
    const exported = await readWorkflowFile(
      file(JSON.stringify({ format: "vuln-veille.workflow/1", name: "W", graph: v1 })),
    );
    expect(exported.name).toBe("W");
    expect((await readWorkflowFile(file(JSON.stringify(v1), "veille.json"))).name).toBe("veille");
    await expect(readWorkflowFile(file("{"))).rejects.toThrow("invalid_json");
    await expect(readWorkflowFile(file('{"a": 1}'))).rejects.toThrow("not_a_workflow");
  });

  function stubVersions(calls: Call[]) {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: Request | string, init?: RequestInit) => {
        const request = typeof input === "string" ? new Request(input, init) : input;
        const url = new URL(request.url);
        const path = url.pathname;
        const text = request.method === "GET" ? "" : await request.clone().text();
        calls.push({
          method: request.method,
          path: path + url.search,
          body: text ? JSON.parse(text) : null,
        });
        const base = "/api/v1/workspaces/voc/workflows/w1";
        const version = (no: number, graph: Graph) => ({
          id: `v${no}`,
          version_no: no,
          comment: `c${no}`,
          graph_hash: "h",
          created_by: null,
          created_at: "2026-10-22T08:00:00Z",
          graph,
        });
        if (path === "/api/v1/auth/me") return Response.json(me);
        if (path === "/api/v1/node-types") return Response.json(TYPES);
        if (path === base) {
          return Response.json({
            ...workflow,
            latest_version_no: 2,
            active_version_no: 2,
            latest_graph: v2,
            versions: [version(2, v2), version(1, v1)],
          });
        }
        if (path === `${base}/versions/1`) return Response.json(version(1, v1));
        if (path === `${base}/versions/2`) return Response.json(version(2, v2));
        if (path === `${base}/versions/1/restore`) {
          return Response.json(version(3, v1), { status: 201 });
        }
        if (path === `${base}/export`) {
          return Response.json({
            format: "vuln-veille.workflow/1",
            name: "N",
            description: "",
            tags: [],
            graph: v1,
          });
        }
        if (path === `${base}/draft`) return Response.json({ detail: "no_draft" }, { status: 404 });
        return Response.json([]);
      }),
    );
  }

  it("compares two versions on the canvas and as JSON", async () => {
    stubVersions([]);
    render(
      <App
        router={createMemoryRouter(routes, {
          initialEntries: ["/workflows/w1/compare?from=1&to=2"],
        })}
      />,
    );
    expect(
      within(await screen.findByTestId("node-summary")).getByText("Ajouté"),
    ).toBeInTheDocument();
    expect(within(screen.getByTestId("node-old")).getByText("Supprimé")).toBeInTheDocument();
    expect(within(screen.getByTestId("node-high")).getByText("Modifié")).toBeInTheDocument();
    expect(within(screen.getByTestId("node-start")).queryByText("Modifié")).toBeNull();
    expect(screen.getByText("params.condition")).toBeInTheDocument();
    expect(screen.getByText(/Liaisons : 1 ajoutée\(s\), 1 supprimée\(s\)/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "JSON" }));
    expect(await screen.findByText(/^- .*json.score >= `7`/)).toBeInTheDocument();
    expect(screen.getByText(/^\+ .*json.score >= `9`/)).toBeInTheDocument();
  });

  it("restores and exports a version from the history", async () => {
    const calls: Call[] = [];
    stubVersions(calls);
    const created: Blob[] = [];
    vi.stubGlobal(
      "URL",
      Object.assign(URL, {
        createObjectURL: (blob: Blob) => {
          created.push(blob);
          return "blob:export";
        },
        revokeObjectURL: () => undefined,
      }),
    );
    render(<App router={createMemoryRouter(routes, { initialEntries: ["/workflows/w1"] })} />);
    fireEvent.click(await screen.findByRole("tab", { name: "Versions" }));
    fireEvent.click(screen.getByRole("button", { name: "Restaurer" }));
    expect(await screen.findByText(/La v1 est republiée comme v3/)).toBeInTheDocument();
    expect(calls).toContainEqual({
      method: "POST",
      path: "/api/v1/workspaces/voc/workflows/w1/versions/1/restore",
      body: { comment: "", base_version_no: 2 },
    });
    fireEvent.click(screen.getAllByRole("button", { name: "Exporter (JSON)" })[1] as HTMLElement);
    await waitFor(() => expect(created).toHaveLength(1));
    expect(calls.some((c) => c.path.endsWith("/export?version_no=1"))).toBe(true);
    expect(JSON.parse(await (created[0] as Blob).text()).format).toBe("vuln-veille.workflow/1");
    expect(screen.getByRole("link", { name: "Comparer avec la précédente" })).toHaveAttribute(
      "href",
      "/workflows/w1/compare?from=1&to=2",
    );
  });

  it("imports a graph into the editor and lists the changes before publishing", async () => {
    stubVersions([]);
    renderEditor();
    await screen.findByTestId("node-summary");
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, {
      target: { files: [new File([JSON.stringify(v1)], "ancienne.json")] },
    });
    expect(await screen.findByTestId("node-old")).toBeInTheDocument();
    expect(screen.queryByTestId("node-summary")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Publier une version" }));
    expect(await screen.findByText("Changements")).toBeInTheDocument();
    expect(screen.getByText("params.condition")).toBeInTheDocument();
  });

  it("explains a schedule in plain words", async () => {
    stubVersions([]);
    renderEditor();
    fireEvent.click(await screen.findByRole("button", { name: "Planification" }));
    fireEvent.change(await screen.findByLabelText("Expression cron"), {
      target: { value: "30 8 * * 1-5" },
    });
    expect(await screen.findByText("À 08:30, de lundi à vendredi")).toBeInTheDocument();
  });
});
