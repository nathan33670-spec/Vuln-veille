import type { FieldError, Schemas } from "@vv/api-client";

/** Graph format schema_version 1 (spec 02 §2), as the editor handles it. */
export type NodeType = Schemas["NodeTypeOut"];

export interface Position {
  x: number;
  y: number;
}

/** Optional fields may hold undefined: dropped when the graph is serialised. */
export interface NodeSettings {
  retry?: { max_attempts?: number | undefined; backoff_seconds?: number | undefined };
  timeout_seconds?: number | undefined;
  on_error?: "stop" | "continue" | "route" | undefined;
}

export interface GraphNode {
  id: string;
  type: string;
  type_version?: number;
  name?: string;
  params: Record<string, unknown>;
  settings?: NodeSettings;
  position?: Position;
}

export interface GraphEdge {
  id: string;
  from: { node: string; port: string };
  to: { node: string; port: string };
}

export interface Graph {
  schema_version: 1;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const CATEGORIES = [
  "trigger",
  "source",
  "transform",
  "ai",
  "vuln",
  "bulletin",
  "output",
  "control",
  "integration",
] as const;

const NODE_ID = /^[a-z][a-z0-9_]{0,63}$/;
const COLUMN = 280;
const ROW = 130;

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/** A graph from the API (draft, version), read defensively: it is shown, never trusted. */
export function parseGraph(raw: unknown): Graph {
  const graph = record(raw);
  const nodes = (Array.isArray(graph.nodes) ? graph.nodes : []).map((value): GraphNode => {
    const n = record(value);
    const position = record(n.position);
    const node: GraphNode = {
      id: String(n.id ?? ""),
      type: String(n.type ?? ""),
      params: { ...record(n.params) },
    };
    if (typeof n.type_version === "number") node.type_version = n.type_version;
    if (typeof n.name === "string" && n.name) node.name = n.name;
    if (n.settings && typeof n.settings === "object") node.settings = n.settings as NodeSettings;
    if (typeof position.x === "number" && typeof position.y === "number") {
      node.position = { x: position.x, y: position.y };
    }
    return node;
  });
  const edges = (Array.isArray(graph.edges) ? graph.edges : []).map((value): GraphEdge => {
    const e = record(value);
    const from = record(e.from);
    const to = record(e.to);
    return {
      id: String(e.id ?? ""),
      from: { node: String(from.node ?? ""), port: String(from.port ?? "out") },
      to: { node: String(to.node ?? ""), port: String(to.port ?? "in") },
    };
  });
  return { schema_version: 1, nodes, edges };
}

/** Positions for nodes without one (delivered workflows): one column per depth. */
export function layout(graph: Graph): Graph {
  if (graph.nodes.every((n) => n.position)) return graph;
  const depth = new Map<string, number>();
  const incoming = new Map<string, string[]>();
  for (const e of graph.edges) {
    incoming.set(e.to.node, [...(incoming.get(e.to.node) ?? []), e.from.node]);
  }
  const visit = (id: string, seen: Set<string>): number => {
    const known = depth.get(id);
    if (known !== undefined) return known;
    if (seen.has(id)) return 0; // a cycle: the server reports it
    seen.add(id);
    const parents = incoming.get(id) ?? [];
    const value = parents.length ? Math.max(...parents.map((p) => visit(p, seen) + 1)) : 0;
    depth.set(id, value);
    return value;
  };
  const rows = new Map<number, number>();
  return {
    ...graph,
    nodes: graph.nodes.map((n) => {
      const column = visit(n.id, new Set());
      const row = rows.get(column) ?? 0;
      rows.set(column, row + 1);
      return n.position ? n : { ...n, position: { x: column * COLUMN, y: row * ROW } };
    }),
  };
}

/** A readable, unique node id derived from its type ("filter", "filter_2"…). */
export function newNodeId(type: string, taken: Iterable<string>): string {
  const used = new Set(taken);
  const base =
    (type.split(".").pop() ?? "node")
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, "_")
      .replace(/^[^a-z]+/, "")
      .slice(0, 56) || "node";
  if (!used.has(base) && NODE_ID.test(base)) return base;
  let i = 2;
  while (used.has(`${base}_${i}`)) i += 1;
  return `${base}_${i}`;
}

export function newEdgeId(taken: Iterable<string>): string {
  const used = new Set(taken);
  let i = used.size + 1;
  while (used.has(`e${i}`)) i += 1;
  return `e${i}`;
}

export interface Connection {
  source: string;
  sourceHandle: string | null;
  target: string;
  targetHandle: string | null;
}

/** Why a connection is refused (an i18n code), or null when it is valid. */
export function connectionError(
  graph: Pick<Graph, "nodes" | "edges">,
  types: ReadonlyMap<string, NodeType>,
  c: Connection,
): string | null {
  if (c.source === c.target) return "self";
  const from = graph.nodes.find((n) => n.id === c.source);
  const to = graph.nodes.find((n) => n.id === c.target);
  const fromType = from && types.get(from.type);
  const toType = to && types.get(to.type);
  if (!fromType || !toType) return "unknown_node_type";
  const fromPort = c.sourceHandle ?? fromType.outputs[0];
  const toPort = c.targetHandle ?? toType.inputs[0];
  if (!fromPort || !fromType.outputs.includes(fromPort)) return "unknown_port";
  if (!toPort || !toType.inputs.includes(toPort)) return "unknown_port";
  if (
    graph.edges.some(
      (e) =>
        e.from.node === c.source &&
        e.from.port === fromPort &&
        e.to.node === c.target &&
        e.to.port === toPort,
    )
  ) {
    return "duplicate";
  }
  // A cycle if the source is already reachable from the target.
  const next = new Map<string, string[]>();
  for (const e of graph.edges) next.set(e.from.node, [...(next.get(e.from.node) ?? []), e.to.node]);
  const stack = [c.target];
  const seen = new Set<string>();
  while (stack.length) {
    const id = stack.pop() as string;
    if (id === c.source) return "cycle";
    if (seen.has(id)) continue;
    seen.add(id);
    stack.push(...(next.get(id) ?? []));
  }
  return null;
}

export interface LocatedError {
  field: string | null;
  code: string;
}

/** Validation errors (paths "nodes.3.params.url") grouped by node id; the rest is global. */
export function locateErrors(
  errors: FieldError[],
  graph: Pick<Graph, "nodes" | "edges">,
): { byNode: Map<string, LocatedError[]>; global: FieldError[] } {
  const byNode = new Map<string, LocatedError[]>();
  const global: FieldError[] = [];
  for (const error of errors) {
    const parts = error.path.split(".");
    let nodeId: string | undefined;
    let field: string | null = null;
    if (parts[0] === "nodes" && parts[1] !== undefined) {
      nodeId = graph.nodes[Number(parts[1])]?.id;
      field = parts[2] === "params" ? (parts[3] ?? null) : (parts[2] ?? null);
    } else if (parts[0] === "edges" && parts[1] !== undefined) {
      nodeId = graph.edges[Number(parts[1])]?.to.node;
    }
    if (nodeId) byNode.set(nodeId, [...(byNode.get(nodeId) ?? []), { field, code: error.code }]);
    else global.push(error);
  }
  return { byNode, global };
}

/** Errors as returned in a draft (loosely typed JSON) → FieldError. */
export function asFieldErrors(raw: unknown): FieldError[] {
  return (Array.isArray(raw) ? raw : []).flatMap((value) => {
    const e = record(value);
    return typeof e.path === "string" && typeof e.code === "string"
      ? [{ path: e.path, code: e.code }]
      : [];
  });
}
