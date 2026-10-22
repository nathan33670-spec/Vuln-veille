import "@xyflow/react/dist/style.css";

import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useNodesInitialized,
  useReactFlow,
} from "@xyflow/react";
import { type ReactNode, useEffect, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";

import type { NodeRun } from "../follow";
import { duration } from "../shared";
import { toFlow } from "./flow";
import type { Graph, NodeType } from "./model";
import { NodeCard } from "./NodeCard";

const NODE_TYPES = { vv: NodeCard };

/** A run on its graph, read-only: status, counters, duration and AI cost per node. */
export function RunCanvas({
  graph,
  types,
  nodeRuns,
  selected,
  onSelect,
}: {
  graph: Graph;
  types: NodeType[];
  nodeRuns: NodeRun[];
  selected: string | undefined;
  onSelect: (nodeId: string) => void;
}) {
  const { t } = useTranslation();
  const typeMap = useMemo(() => new Map(types.map((nt) => [nt.type, nt])), [types]);
  const base = useMemo(() => toFlow(graph, typeMap), [graph, typeMap]);
  const nodes = useMemo(() => {
    // The last attempt of each node.
    const last = new Map<string, NodeRun>();
    for (const n of nodeRuns) {
      const known = last.get(n.node_id);
      if (!known || n.attempt >= known.attempt) last.set(n.node_id, n);
    }
    return base.nodes.map((n) => {
      const run = last.get(n.id);
      const summary = run
        ? [
            `${run.input_count} → ${run.output_count}`,
            run.finished_at ? duration(run.started_at, run.finished_at) : null,
            run.ai_calls
              ? t("runs.aiCost", { cost: Number(run.ai_cost_usd ?? 0).toFixed(4) })
              : null,
          ]
            .filter(Boolean)
            .join(" · ")
        : undefined;
      return {
        ...n,
        selected: n.id === selected,
        data: { ...n.data, status: run?.status, summary },
      };
    });
  }, [base, nodeRuns, selected, t]);
  return (
    <div className="vv-run-canvas">
      <ReactFlowProvider>
        <Framed />
        <ReactFlow
          nodes={nodes}
          edges={base.edges}
          nodeTypes={NODE_TYPES}
          nodesDraggable={false}
          nodesConnectable={false}
          deleteKeyCode={null}
          onNodeClick={(_, node) => onSelect(node.id)}
          minZoom={0.1}
          proOptions={{ hideAttribution: true }}
        >
          <Background />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable />
        </ReactFlow>
      </ReactFlowProvider>
    </div>
  );
}

/** Frames the graph once its nodes are measured. */
function Framed(): ReactNode {
  const flow = useReactFlow();
  const measured = useNodesInitialized();
  const framed = useRef(false);
  useEffect(() => {
    if (!measured || framed.current) return;
    framed.current = true;
    void flow.fitView({ padding: 0.1 });
  }, [measured, flow]);
  return null;
}
