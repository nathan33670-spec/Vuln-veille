import "@xyflow/react/dist/style.css";

import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Card, PageHeader, SelectField, Tabs } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import {
  Background,
  Controls,
  type Edge,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useNodesInitialized,
  useReactFlow,
} from "@xyflow/react";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams, useSearchParams } from "react-router";

import { client } from "../../../api";
import { useWorkspace } from "../../../workspace";
import { comparableJson, diffGraphs, type GraphDiff, lineDiff } from "./diff";
import { layout, type NodeType, parseGraph, type Graph } from "./model";
import { type EditorNode, NodeCard } from "./NodeCard";

const NODE_TYPES = { vv: NodeCard };
export const DRAFT = "draft";

/** Two versions of a workflow (or the draft) side by side: on the canvas, and as JSON. */
export function ComparePage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug } = useWorkspace();
  const workspace = slug ?? "";
  const [params, setParams] = useSearchParams();
  const [view, setView] = useState<"graph" | "json">("graph");
  const detail = useQuery({
    queryKey: ["workflow", workspace, id],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/workflows/{workflow_id}", {
          params: { path: { workspace, workflow_id: id } },
        }),
      ),
  });
  const latest = detail.data?.latest_version_no ?? 0;
  const to = params.get("to") ?? String(latest);
  const from = params.get("from") ?? String(Math.max(1, Number(to) - 1));
  const before = useGraph(workspace, id, from);
  const after = useGraph(workspace, id, to);
  const types = useQuery({
    queryKey: ["node-types"],
    staleTime: 5 * 60_000,
    queryFn: async () => unwrap(await client.GET("/api/v1/node-types")),
  });
  const diff = useMemo(
    () => (before.data && after.data ? diffGraphs(before.data, after.data) : null),
    [before.data, after.data],
  );

  const failed = detail.error ?? before.error ?? after.error ?? types.error;
  if (failed) return <Alert>{errorMessage(t, failed)}</Alert>;
  if (!detail.data) return <p className="vv-muted">{t("auth.loading")}</p>;
  const options = [
    ...detail.data.versions.map((v) => ({
      value: String(v.version_no),
      label: `v${v.version_no}${v.comment ? ` — ${v.comment}` : ""}`,
    })),
    { value: DRAFT, label: t("workflows.compare.draft") },
  ];
  const choose = (key: "from" | "to", value: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    if (!next.get(key === "from" ? "to" : "from")) {
      next.set(key === "from" ? "to" : "from", key === "from" ? to : from);
    }
    setParams(next);
  };

  return (
    <>
      <PageHeader
        title={t("workflows.compare.title", { name: detail.data.name })}
        actions={<Link to={`/workflows/${id}`}>{t("workflows.editor.back")}</Link>}
      />
      <div className="vv-actions">
        <SelectField
          label={t("workflows.compare.from")}
          value={from}
          onChange={(v) => choose("from", v)}
          options={options}
        />
        <SelectField
          label={t("workflows.compare.to")}
          value={to}
          onChange={(v) => choose("to", v)}
          options={options}
        />
      </div>
      <Tabs<"graph" | "json">
        label={t("workflows.compare.views")}
        value={view}
        onChange={setView}
        options={[
          { value: "graph", label: t("workflows.graph") },
          { value: "json", label: "JSON" },
        ]}
      />
      {!diff || !before.data || !after.data || !types.data ? (
        <p className="vv-muted">{t("auth.loading")}</p>
      ) : view === "graph" ? (
        <div className="vv-compare">
          <DiffCanvas diff={diff} after={after.data} before={before.data} types={types.data} />
          <ChangeList diff={diff} />
        </div>
      ) : (
        <JsonDiff before={before.data} after={after.data} />
      )}
    </>
  );
}

/** A version's graph, or the draft's ("draft"). */
function useGraph(workspace: string, workflowId: string, which: string) {
  return useQuery({
    queryKey: ["workflow-graph", workspace, workflowId, which],
    enabled: Boolean(workspace && which && which !== "0"),
    staleTime: which === DRAFT ? 0 : Infinity, // versions are immutable
    queryFn: async (): Promise<Graph> => {
      const path = { workspace, workflow_id: workflowId };
      if (which === DRAFT) {
        const draft = await client.GET(
          "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/draft",
          { params: { path } },
        );
        return parseGraph(unwrap(draft).graph);
      }
      const version = unwrap(
        await client.GET(
          "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/versions/{version_no}",
          { params: { path: { ...path, version_no: Number(which) } } },
        ),
      );
      return parseGraph(version.graph);
    },
  });
}

function DiffCanvas({
  diff,
  before,
  after,
  types,
}: {
  diff: GraphDiff;
  before: Graph;
  after: Graph;
  types: NodeType[];
}) {
  const typeMap = useMemo(() => new Map(types.map((nt) => [nt.type, nt])), [types]);
  const { nodes, edges } = useMemo(() => {
    const placed = layout({
      ...after,
      nodes: diff.merged,
      edges: [...after.edges, ...before.edges],
    });
    const flowNodes: EditorNode[] = placed.nodes.map((node) => ({
      id: node.id,
      type: "vv",
      position: node.position ?? { x: 0, y: 0 },
      data: {
        node,
        type: typeMap.get(node.type),
        errorCount: 0,
        diff: diff.nodes.get(node.id),
      },
    }));
    const added = new Set(diff.edges.added.map((e) => e.id));
    const flowEdges: Edge[] = [
      ...after.edges.map((e) => ({
        id: `a:${e.id}`,
        source: e.from.node,
        sourceHandle: e.from.port,
        target: e.to.node,
        targetHandle: e.to.port,
        className: added.has(e.id) ? "vv-edge-added" : "",
      })),
      ...diff.edges.removed.map((e) => ({
        id: `r:${e.id}`,
        source: e.from.node,
        sourceHandle: e.from.port,
        target: e.to.node,
        targetHandle: e.to.port,
        className: "vv-edge-removed",
      })),
    ];
    return { nodes: flowNodes, edges: flowEdges };
  }, [diff, before, after, typeMap]);
  return (
    <div className="vv-run-canvas">
      <ReactFlowProvider>
        <Framed />
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          nodesDraggable={false}
          nodesConnectable={false}
          deleteKeyCode={null}
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

const shown = (value: unknown) => {
  const text = value === undefined ? "—" : JSON.stringify(value);
  return text.length > 300 ? `${text.slice(0, 300)}…` : text;
};

/** The changes, node by node: what was added, removed, and each changed field. */
export function ChangeList({ diff }: { diff: GraphDiff }) {
  const { t } = useTranslation();
  const changed = [...diff.nodes.entries()].filter(([, kind]) => kind !== "same");
  const edges = diff.edges.added.length + diff.edges.removed.length;
  if (changed.length === 0 && edges === 0) {
    return <p className="vv-muted">{t("workflows.compare.none")}</p>;
  }
  return (
    <Card title={t("workflows.compare.changes")}>
      <ul className="vv-change-list">
        {changed.map(([nodeId, kind]) => (
          <li key={nodeId} className={`vv-change-${kind}`}>
            <strong>{t(`workflows.compare.kinds.${kind}`)}</strong> <code>{nodeId}</code>
            {(diff.fields.get(nodeId) ?? []).map((f) => (
              <div key={f.path} className="vv-change-field">
                <code>{f.path}</code> : <span className="vv-diff-del">{shown(f.before)}</span> →{" "}
                <span className="vv-diff-add">{shown(f.after)}</span>
              </div>
            ))}
          </li>
        ))}
        {edges ? (
          <li>
            {t("workflows.compare.edges", {
              added: diff.edges.added.length,
              removed: diff.edges.removed.length,
            })}
          </li>
        ) : null}
      </ul>
    </Card>
  );
}

function JsonDiff({ before, after }: { before: Graph; after: Graph }) {
  const lines = useMemo(
    () => lineDiff(comparableJson(before), comparableJson(after)),
    [before, after],
  );
  return (
    <pre className="vv-pre vv-json-diff">
      {lines.map((line, i) => (
        <div
          key={i}
          className={line.op === "+" ? "vv-diff-add" : line.op === "-" ? "vv-diff-del" : ""}
        >
          {line.op} {line.text}
        </div>
      ))}
    </pre>
  );
}
