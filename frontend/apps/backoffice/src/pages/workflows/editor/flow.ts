import type { Edge } from "@xyflow/react";

import { type Graph, layout, type NodeType } from "./model";
import type { EditorNode } from "./NodeCard";

/** The canvas state: React Flow nodes (carrying the graph nodes) and edges. */
export interface Snapshot {
  nodes: EditorNode[];
  edges: Edge[];
}

export function toFlow(graph: Graph, types: ReadonlyMap<string, NodeType>): Snapshot {
  const placed = layout(graph);
  return {
    nodes: placed.nodes.map((node) => ({
      id: node.id,
      type: "vv",
      position: node.position ?? { x: 0, y: 0 },
      data: { node, type: types.get(node.type), errorCount: 0 },
    })),
    edges: placed.edges.map((e) => ({
      id: e.id,
      source: e.from.node,
      sourceHandle: e.from.port,
      target: e.to.node,
      targetHandle: e.to.port,
    })),
  };
}

export function toGraph(nodes: EditorNode[], edges: Edge[]): Graph {
  return {
    schema_version: 1,
    nodes: nodes.map((n) => ({
      ...n.data.node,
      position: { x: Math.round(n.position.x), y: Math.round(n.position.y) },
    })),
    edges: edges.map((e) => ({
      id: e.id,
      from: { node: e.source, port: e.sourceHandle ?? "out" },
      to: { node: e.target, port: e.targetHandle ?? "in" },
    })),
  };
}
