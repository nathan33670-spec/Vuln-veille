import type { Graph, GraphEdge, GraphNode } from "./model";

export type DiffKind = "added" | "removed" | "modified" | "same";

export interface FieldChange {
  path: string;
  before: unknown;
  after: unknown;
}

export interface GraphDiff {
  nodes: Map<string, DiffKind>;
  /** Changed fields of modified nodes (type, name, params.*, settings.*). */
  fields: Map<string, FieldChange[]>;
  edges: { added: GraphEdge[]; removed: GraphEdge[] };
  /** The nodes of both graphs: those of `after`, then those only in `before`. */
  merged: GraphNode[];
}

/** A key-sorted JSON text: two equal values always give the same text. */
export function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
        )
      : v,
  );
}

function compareRecords(
  prefix: string,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): FieldChange[] {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  return keys
    .filter((key) => stableJson(before[key]) !== stableJson(after[key]))
    .map((key) => ({ path: `${prefix}.${key}`, before: before[key], after: after[key] }));
}

function nodeFields(before: GraphNode, after: GraphNode): FieldChange[] {
  const changes: FieldChange[] = [];
  if (before.type !== after.type) {
    changes.push({ path: "type", before: before.type, after: after.type });
  }
  if ((before.name ?? "") !== (after.name ?? "")) {
    changes.push({ path: "name", before: before.name ?? "", after: after.name ?? "" });
  }
  changes.push(...compareRecords("params", before.params, after.params));
  changes.push(
    ...compareRecords(
      "settings",
      (before.settings ?? {}) as Record<string, unknown>,
      (after.settings ?? {}) as Record<string, unknown>,
    ),
  );
  return changes;
}

const edgeKey = (e: GraphEdge) => `${e.from.node}.${e.from.port}>${e.to.node}.${e.to.port}`;

/** What changed between two graphs; positions are layout, not changes. */
export function diffGraphs(before: Graph, after: Graph): GraphDiff {
  const old = new Map(before.nodes.map((n) => [n.id, n]));
  const current = new Map(after.nodes.map((n) => [n.id, n]));
  const nodes = new Map<string, DiffKind>();
  const fields = new Map<string, FieldChange[]>();
  for (const node of after.nodes) {
    const previous = old.get(node.id);
    if (!previous) {
      nodes.set(node.id, "added");
      continue;
    }
    const changes = nodeFields(previous, node);
    nodes.set(node.id, changes.length ? "modified" : "same");
    if (changes.length) fields.set(node.id, changes);
  }
  const removed = before.nodes.filter((n) => !current.has(n.id));
  for (const node of removed) nodes.set(node.id, "removed");
  const oldEdges = new Set(before.edges.map(edgeKey));
  const newEdges = new Set(after.edges.map(edgeKey));
  return {
    nodes,
    fields,
    edges: {
      added: after.edges.filter((e) => !oldEdges.has(edgeKey(e))),
      removed: before.edges.filter((e) => !newEdges.has(edgeKey(e))),
    },
    merged: [...after.nodes, ...removed],
  };
}

export function hasChanges(diff: GraphDiff): boolean {
  return (
    [...diff.nodes.values()].some((c) => c !== "same") ||
    diff.edges.added.length > 0 ||
    diff.edges.removed.length > 0
  );
}

export interface DiffLine {
  op: " " | "+" | "-";
  text: string;
}

const MAX_CELLS = 4_000_000;

/** Line diff of two texts (longest common subsequence), for the JSON view. */
export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  if (a.length * b.length > MAX_CELLS) {
    // Too large for the table: everything old removed, everything new added.
    return [
      ...a.map((text) => ({ op: "-" as const, text })),
      ...b.map((text) => ({ op: "+" as const, text })),
    ];
  }
  const width = b.length + 1;
  const table = new Uint32Array((a.length + 1) * width);
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      table[i * width + j] =
        a[i] === b[j]
          ? (table[(i + 1) * width + j + 1] ?? 0) + 1
          : Math.max(table[(i + 1) * width + j] ?? 0, table[i * width + j + 1] ?? 0);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ op: " ", text: a[i] ?? "" });
      i += 1;
      j += 1;
    } else if ((table[(i + 1) * width + j] ?? 0) >= (table[i * width + j + 1] ?? 0)) {
      out.push({ op: "-", text: a[i] ?? "" });
      i += 1;
    } else {
      out.push({ op: "+", text: b[j] ?? "" });
      j += 1;
    }
  }
  for (; i < a.length; i += 1) out.push({ op: "-", text: a[i] ?? "" });
  for (; j < b.length; j += 1) out.push({ op: "+", text: b[j] ?? "" });
  return out;
}

/** A graph as compared in the JSON view: key-sorted, positions left out. */
export function comparableJson(graph: Graph): string {
  const stripped = {
    nodes: graph.nodes.map((n) => ({ ...n, position: undefined })),
    edges: graph.edges,
  };
  return JSON.stringify(JSON.parse(stableJson(stripped)), null, 2);
}
