import "@xyflow/react/dist/style.css";

import { ApiError, type FieldError, type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, Dialog, PageHeader, TextField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  type Connection as FlowConnection,
  Controls,
  type Edge,
  type EdgeChange,
  MiniMap,
  type NodeChange,
  ReactFlow,
  ReactFlowProvider,
  useNodesInitialized,
  useReactFlow,
} from "@xyflow/react";
import {
  type DragEvent,
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";

import { client } from "../../../api";
import { formatDate } from "../../../lib";
import { useWorkspace } from "../../../workspace";
import { GraphErrors } from "../shared";
import {
  asFieldErrors,
  connectionError,
  type Graph,
  type GraphNode,
  layout,
  locateErrors,
  newEdgeId,
  newNodeId,
  type NodeType,
  parseGraph,
} from "./model";
import { type EditorNode, NodeCard } from "./NodeCard";
import { DRAG_TYPE, Palette } from "./Palette";
import { type Choices, ParamsPanel } from "./ParamsPanel";

type Draft = Schemas["DraftOut"];
type Detail = Schemas["WorkflowDetailOut"];

const NODE_TYPES = { vv: NodeCard };
const AUTOSAVE_MS = 1200;
const HISTORY = 100;

export function EditorPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug, can } = useWorkspace();
  const workspace = slug ?? "";
  const path = { params: { path: { workspace, workflow_id: id } } };
  const [generation, setGeneration] = useState(0);
  const detail = useQuery({
    queryKey: ["workflow", workspace, id],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/workflows/{workflow_id}", path)),
  });
  const draft = useQuery({
    queryKey: ["workflow-draft", workspace, id, generation],
    enabled: Boolean(slug),
    queryFn: async (): Promise<Draft | null> => {
      const response = await client.GET(
        "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/draft",
        path,
      );
      if (response.response.status === 404) return null;
      return unwrap(response);
    },
  });
  const types = useQuery({
    queryKey: ["node-types"],
    staleTime: 5 * 60_000,
    queryFn: async () => unwrap(await client.GET("/api/v1/node-types")),
  });
  const connectors = useQuery({
    queryKey: ["connectors", workspace, "source"],
    enabled: Boolean(slug) && can("connector.source.manage"),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/connectors/source", {
          params: { path: { workspace } },
        }),
      ),
  });
  const agents = useQuery({
    queryKey: ["agents", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/agents", {
          params: { path: { workspace } },
        }),
      ),
  });

  const failed = detail.error ?? draft.error ?? types.error;
  if (failed) return <Alert>{errorMessage(t, failed)}</Alert>;
  if (!detail.data || draft.data === undefined || !types.data) {
    return <p className="vv-muted">{t("auth.loading")}</p>;
  }
  const choices: Choices = {
    connectors: connectors.data ?? null,
    agents: agents.data ?? null,
  };
  return (
    <ReactFlowProvider key={`${id}:${generation}`}>
      <Editor
        workspace={workspace}
        detail={detail.data}
        draft={draft.data}
        types={types.data}
        choices={choices}
        readOnly={!can("workflow.edit")}
        can={can}
        onReload={() => setGeneration((g) => g + 1)}
      />
    </ReactFlowProvider>
  );
}

interface Snapshot {
  nodes: EditorNode[];
  edges: Edge[];
}

interface History {
  past: Snapshot[];
  future: Snapshot[];
  key: string | null;
}

type SaveState =
  | { kind: "idle" }
  | { kind: "pending" }
  | { kind: "saved"; at: string }
  | { kind: "error"; message: string };

function toFlow(graph: Graph, types: ReadonlyMap<string, NodeType>): Snapshot {
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

function toGraph(nodes: EditorNode[], edges: Edge[]): Graph {
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

function Editor({
  workspace,
  detail,
  draft,
  types,
  choices,
  readOnly,
  can,
  onReload,
}: {
  workspace: string;
  detail: Detail;
  draft: Draft | null;
  types: NodeType[];
  choices: Choices;
  readOnly: boolean;
  can: (permission: string) => boolean;
  onReload: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const flow = useReactFlow<EditorNode, Edge>();
  const typeMap = useMemo(() => new Map(types.map((nt) => [nt.type, nt])), [types]);
  const draftPath = {
    params: { path: { workspace, workflow_id: detail.id } },
  };
  const [initial] = useState(() =>
    toFlow(parseGraph(draft?.graph ?? detail.latest_graph ?? { nodes: [] }), typeMap),
  );
  const [nodes, setNodes] = useState<EditorNode[]>(initial.nodes);
  const [edges, setEdges] = useState<Edge[]>(initial.edges);
  const [base, setBase] = useState<number | null>(
    draft ? draft.base_version_no : (detail.latest_version_no ?? null),
  );
  const [stale, setStale] = useState(Boolean(draft?.stale));
  const [errors, setErrors] = useState<{ list: FieldError[]; graph: Graph }>(() => ({
    list: asFieldErrors(draft?.errors),
    graph: toGraph(initial.nodes, initial.edges),
  }));
  const [saveState, setSaveState] = useState<SaveState>(
    draft ? { kind: "saved", at: draft.updated_at } : { kind: "idle" },
  );
  const [message, setMessage] = useState<{ tone: "error" | "success" | "info"; text: string }>();
  const [conflict, setConflict] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [revision, setRevision] = useState(0);
  const [history, setHistory] = useState<History>({ past: [], future: [], key: null });
  const graph = useMemo(() => toGraph(nodes, edges), [nodes, edges]);
  const graphJson = JSON.stringify(graph);
  const saved = useRef(graphJson);

  const located = useMemo(() => locateErrors(errors.list, errors.graph), [errors]);
  const shownNodes = useMemo(
    () =>
      nodes.map((n) => {
        const count = located.byNode.get(n.id)?.length ?? 0;
        return count === n.data.errorCount ? n : { ...n, data: { ...n.data, errorCount: count } };
      }),
    [nodes, located],
  );
  const selected = nodes.find((n) => n.selected);

  // Framed once the nodes are measured (fitView alone runs before the canvas has its size).
  const measured = useNodesInitialized();
  const framed = useRef(false);
  useEffect(() => {
    if (!measured || framed.current) return;
    framed.current = true;
    void flow.fitView({ padding: 0.1 });
  }, [measured, flow]);

  // Server-side draft: saved shortly after each change, with its validation errors.
  useEffect(() => {
    if (readOnly || graphJson === saved.current) return;
    setSaveState({ kind: "pending" });
    const timer = window.setTimeout(async () => {
      const sent = JSON.parse(graphJson) as Graph;
      try {
        const result = unwrap(
          await client.PUT("/api/v1/workspaces/{workspace}/workflows/{workflow_id}/draft", {
            params: { path: { workspace, workflow_id: detail.id } },
            body: { graph: sent as unknown as Record<string, unknown>, base_version_no: base },
          }),
        );
        saved.current = graphJson;
        setErrors({ list: asFieldErrors(result.errors), graph: sent });
        setStale(result.stale);
        setSaveState({ kind: "saved", at: result.updated_at });
      } catch (err) {
        setSaveState({ kind: "error", message: errorMessage(t, err) });
      }
    }, AUTOSAVE_MS);
    return () => window.clearTimeout(timer);
  }, [graphJson, base, readOnly, t, workspace, detail.id]);

  function record(key: string | null = null) {
    if (key !== null && history.key === key) return; // successive edits of one field: one step
    setHistory({ past: [...history.past.slice(1 - HISTORY), { nodes, edges }], future: [], key });
  }

  function travel(direction: "undo" | "redo") {
    const from = direction === "undo" ? history.past : history.future;
    const target = from.at(-1);
    if (!target) return;
    const current = { nodes, edges };
    setHistory(
      direction === "undo"
        ? { past: from.slice(0, -1), future: [...history.future, current], key: null }
        : { past: [...history.past, current], future: from.slice(0, -1), key: null },
    );
    setNodes(target.nodes);
    setEdges(target.edges);
    setRevision((r) => r + 1);
  }

  function onNodesChange(changes: NodeChange<EditorNode>[]) {
    const effective = readOnly ? changes.filter((c) => c.type !== "remove") : changes;
    if (effective.some((c) => c.type === "remove")) record();
    setNodes((current) => applyNodeChanges(effective, current));
  }

  function onEdgesChange(changes: EdgeChange[]) {
    const effective = readOnly ? changes.filter((c) => c.type !== "remove") : changes;
    if (effective.some((c) => c.type === "remove")) record();
    setEdges((current) => applyEdgeChanges(effective, current));
  }

  function refusal(c: FlowConnection | Edge): string | null {
    return connectionError(graph, typeMap, {
      source: c.source,
      sourceHandle: c.sourceHandle ?? null,
      target: c.target,
      targetHandle: c.targetHandle ?? null,
    });
  }

  function onConnect(c: FlowConnection) {
    const refused = refusal(c);
    if (refused) {
      setMessage({ tone: "error", text: t(`workflows.editor.refused.${refused}`) });
      return;
    }
    record();
    setEdges((current) => [
      ...current,
      {
        id: newEdgeId(current.map((e) => e.id)),
        source: c.source,
        sourceHandle: c.sourceHandle ?? typeMap.get(nodeType(c.source))?.outputs[0] ?? "out",
        target: c.target,
        targetHandle: c.targetHandle ?? typeMap.get(nodeType(c.target))?.inputs[0] ?? "in",
      },
    ]);
  }

  function nodeType(nodeId: string): string {
    return nodes.find((n) => n.id === nodeId)?.data.node.type ?? "";
  }

  function addNode(typeName: string, position?: { x: number; y: number }) {
    if (readOnly) return;
    const type = typeMap.get(typeName);
    if (!type) return;
    record();
    const nodeId = newNodeId(
      typeName,
      nodes.map((n) => n.id),
    );
    const at = position ?? {
      x: Math.max(0, ...nodes.map((n) => n.position.x)) + (nodes.length ? 280 : 0),
      y: nodes.length ? Math.min(...nodes.map((n) => n.position.y)) : 0,
    };
    const node: GraphNode = { id: nodeId, type: typeName, params: {} };
    setNodes((current) => [
      ...current.map((n) => (n.selected ? { ...n, selected: false } : n)),
      { id: nodeId, type: "vv", position: at, selected: true, data: { node, type, errorCount: 0 } },
    ]);
  }

  function updateNode(updated: GraphNode, field: string) {
    record(`${updated.id}:${field}`);
    setNodes((current) =>
      current.map((n) => (n.id === updated.id ? { ...n, data: { ...n.data, node: updated } } : n)),
    );
  }

  function deleteNode(nodeId: string) {
    record();
    setNodes((current) => current.filter((n) => n.id !== nodeId));
    setEdges((current) => current.filter((e) => e.source !== nodeId && e.target !== nodeId));
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const typeName = event.dataTransfer.getData(DRAG_TYPE);
    if (typeName)
      addNode(typeName, flow.screenToFlowPosition({ x: event.clientX, y: event.clientY }));
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const target = event.target as HTMLElement;
    if (readOnly || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
    if (!(event.ctrlKey || event.metaKey)) return;
    const key = event.key.toLowerCase();
    if (key === "z") {
      event.preventDefault();
      travel(event.shiftKey ? "redo" : "undo");
    } else if (key === "y") {
      event.preventDefault();
      travel("redo");
    }
  }

  async function discardDraft() {
    try {
      await client.DELETE(
        "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/draft",
        draftPath,
      );
    } finally {
      await queryClient.invalidateQueries({ queryKey: ["workflow", workspace, detail.id] });
      onReload();
    }
  }

  async function keepMine() {
    const latest = unwrap(
      await client.GET("/api/v1/workspaces/{workspace}/workflows/{workflow_id}", draftPath),
    );
    setBase(latest.latest_version_no ?? null);
    setStale(false);
    setConflict(false);
    saved.current = ""; // the draft is saved again on its new base
    setMessage({ tone: "info", text: t("workflows.editor.rebased") });
  }

  async function publish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const comment = String(new FormData(event.currentTarget).get("comment") ?? "");
    setPublishing(false);
    try {
      const version = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/workflows/{workflow_id}/versions", {
          ...draftPath,
          body: {
            graph: graph as unknown as Record<string, unknown>,
            comment,
            base_version_no: base ?? 0,
          },
        }),
      );
      await client.DELETE(
        "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/draft",
        draftPath,
      );
      saved.current = graphJson;
      setBase(version.version_no);
      setStale(false);
      setErrors({ list: [], graph });
      setSaveState({ kind: "idle" });
      setMessage({
        tone: "success",
        text: t("workflows.versionSaved", { version: version.version_no }),
      });
      await queryClient.invalidateQueries({ queryKey: ["workflow", workspace, detail.id] });
      await queryClient.invalidateQueries({ queryKey: ["workflows", workspace] });
    } catch (err) {
      if (err instanceof ApiError && err.code === "version_conflict") {
        setConflict(true);
        return;
      }
      if (err instanceof ApiError && err.errors.length) setErrors({ list: err.errors, graph });
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  return (
    <>
      <PageHeader
        title={t("workflows.editor.title", { name: detail.name })}
        actions={
          <span className="vv-actions">
            <SaveStatus state={saveState} readOnly={readOnly} />
            {readOnly ? null : (
              <>
                <Button
                  variant="secondary"
                  disabled={history.past.length === 0}
                  onClick={() => travel("undo")}
                >
                  {t("workflows.editor.undo")}
                </Button>
                <Button
                  variant="secondary"
                  disabled={history.future.length === 0}
                  onClick={() => travel("redo")}
                >
                  {t("workflows.editor.redo")}
                </Button>
                <Button onClick={() => setPublishing(true)}>{t("workflows.editor.publish")}</Button>
              </>
            )}
            <Link to={`/workflows/${detail.id}`}>{t("workflows.editor.back")}</Link>
          </span>
        }
      />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {stale || conflict ? (
        <Alert tone="info">
          {t(conflict ? "workflows.editor.conflict" : "workflows.editor.stale", {
            base: base ?? 0,
            latest: draft?.latest_version_no ?? detail.latest_version_no ?? 0,
          })}{" "}
          <span className="vv-actions">
            <Button variant="secondary" onClick={() => void discardDraft()}>
              {t("workflows.editor.reloadLatest")}
            </Button>
            <Button variant="secondary" onClick={() => void keepMine()}>
              {t("workflows.editor.keepMine")}
            </Button>
          </span>
        </Alert>
      ) : null}
      <GraphErrors errors={located.global} />
      <div className="vv-editor" onKeyDown={onKeyDown}>
        {readOnly ? (
          <div />
        ) : (
          <Palette types={types} can={can} onAdd={(typeName) => addNode(typeName)} />
        )}
        <div
          className="vv-editor-canvas"
          onDragOver={(e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = "move";
          }}
          onDrop={onDrop}
        >
          <ReactFlow<EditorNode, Edge>
            nodes={shownNodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeDragStart={() => record()}
            isValidConnection={(c) => refusal(c) === null}
            nodesDraggable={!readOnly}
            nodesConnectable={!readOnly}
            deleteKeyCode={readOnly ? null : ["Backspace", "Delete"]}
            fitView
            minZoom={0.1}
            proOptions={{ hideAttribution: true }}
          >
            <Background />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable />
          </ReactFlow>
        </div>
        <aside className="vv-editor-side">
          {selected ? (
            <ParamsPanel
              key={`${selected.id}:${revision}`}
              node={selected.data.node}
              type={selected.data.type}
              errors={located.byNode.get(selected.id) ?? []}
              choices={choices}
              readOnly={readOnly}
              onChange={updateNode}
              onDelete={() => deleteNode(selected.id)}
            />
          ) : (
            <p className="vv-muted">{t("workflows.editor.selectHint")}</p>
          )}
        </aside>
      </div>
      <Dialog
        open={publishing}
        title={t("workflows.editor.publish")}
        onClose={() => setPublishing(false)}
      >
        <form className="vv-form" onSubmit={publish}>
          <p className="vv-muted">{t("workflows.editor.publishHint")}</p>
          <TextField label={t("workflows.comment")} name="comment" maxLength={500} />
          <div className="vv-actions">
            <Button type="submit">{t("workflows.editor.publish")}</Button>
            <Button variant="secondary" onClick={() => setPublishing(false)}>
              {t("common.cancel")}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

function SaveStatus({ state, readOnly }: { state: SaveState; readOnly: boolean }) {
  const { t } = useTranslation();
  if (readOnly) return <span className="vv-muted">{t("workflows.editor.readOnly")}</span>;
  switch (state.kind) {
    case "idle":
      return null;
    case "pending":
      return <span className="vv-muted">{t("workflows.editor.saving")}</span>;
    case "saved":
      return (
        <span className="vv-muted">
          {t("workflows.editor.saved", { at: formatDate(state.at) })}
        </span>
      );
    case "error":
      return <span className="vv-field-error">{state.message}</span>;
  }
}
