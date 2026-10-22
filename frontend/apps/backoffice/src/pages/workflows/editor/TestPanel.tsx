import { ApiError, type FieldError, type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, Dialog, SelectField, TextField } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../../api";
import { formatDate } from "../../../lib";
import { followRun } from "../follow";
import { NodeResult } from "../NodeResult";
import { JsonBlock, StatusBadge, TERMINAL } from "../shared";
import type { Item } from "./ExpressionField";
import type { Graph, GraphNode, NodeType } from "./model";

type NodeRunDetail = Schemas["NodeRunDetailOut"];
export type Pins = Record<string, Item[]>;

const MAX_PINNED = 200;

function asItems(value: unknown): Item[] {
  return (Array.isArray(value) ? value : []).flatMap((entry) =>
    entry && typeof entry === "object" && "json" in entry && entry.json ? [entry as Item] : [],
  );
}

/** "Tester ce nœud": pinned inputs (a real CVE, an upstream output), run alone, result. */
export function TestPanel({
  workspace,
  workflowId,
  node,
  type,
  graph,
  pins,
  onPins,
  onStatus,
  onErrors,
}: {
  workspace: string;
  workflowId: string;
  node: GraphNode;
  type: NodeType | undefined;
  graph: Graph;
  pins: Pins;
  onPins: (pins: Pins) => void;
  onStatus: (nodeId: string, status: string | undefined) => void;
  onErrors: (errors: FieldError[]) => void;
}) {
  const { t } = useTranslation();
  const [message, setMessage] = useState<{ tone: "error" | "info"; text: string }>();
  const [confirming, setConfirming] = useState(false);
  const [runId, setRunId] = useState<string>();
  const [status, setStatus] = useState<string>();
  const [result, setResult] = useState<NodeRunDetail>();
  const stop = useRef<(() => void) | null>(null);
  const inputs = type?.inputs ?? [];
  const ai = type?.category === "ai";

  useEffect(() => () => stop.current?.(), []);

  if (!type) return <Alert>{t("workflows.graphErrors.unknown_node_type")}</Alert>;
  if (inputs.length === 0) return <p className="vv-muted">{t("workflows.editor.test.noInput")}</p>;

  const pinned = Object.values(pins).reduce((n, items) => n + items.length, 0);

  async function start() {
    setConfirming(false);
    setMessage(undefined);
    setResult(undefined);
    stop.current?.();
    try {
      const started = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/workflows/{workflow_id}/test-node", {
          params: { path: { workspace, workflow_id: workflowId } },
          body: {
            node_id: node.id,
            graph: graph as unknown as Record<string, unknown>,
            inputs: pins as unknown as Record<string, Record<string, unknown>[]>,
          },
        }),
      );
      setRunId(started.run_id);
      setStatus("queued");
      onStatus(node.id, "queued");
      stop.current = followRun(workspace, started.run_id, {
        onNode: (n) => {
          if (n.node_id !== node.id) return;
          setStatus(n.status);
          onStatus(node.id, n.status);
        },
        onRun: (runStatus, error) => {
          if (!TERMINAL.has(runStatus)) return;
          if (error) setMessage({ tone: "error", text: error });
          void loadResult(started.run_id);
        },
      });
    } catch (err) {
      if (err instanceof ApiError && err.errors.length) onErrors(err.errors);
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  async function loadResult(id: string) {
    try {
      const detail = unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/runs/{run_id}/nodes/{node_id}", {
          params: { path: { workspace, run_id: id, node_id: node.id } },
        }),
      );
      setResult(detail);
      setStatus(detail.status);
      onStatus(node.id, detail.status);
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  return (
    <section className="vv-editor-panel" aria-label={t("workflows.editor.test.title")}>
      <h2 className="vv-card-title">{t("workflows.editor.test.title")}</h2>
      <p className="vv-muted">{t("workflows.editor.test.hint")}</p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <CveSource
        workspace={workspace}
        ports={inputs}
        onLoad={(port, items) => onPins({ ...pins, [port]: items })}
      />
      <UpstreamSource
        workspace={workspace}
        workflowId={workflowId}
        node={node}
        graph={graph}
        onLoad={(port, items) => onPins({ ...pins, [port]: items.slice(0, MAX_PINNED) })}
      />
      <h3>{t("workflows.editor.test.pinned", { count: pinned })}</h3>
      {Object.entries(pins).map(([port, items]) => (
        <details key={port}>
          <summary>
            {t("workflows.editor.test.port", { port, count: items.length })}{" "}
            <Button variant="secondary" onClick={() => onPins(withoutPort(pins, port))}>
              {t("common.remove")}
            </Button>
          </summary>
          <JsonBlock value={items} />
        </details>
      ))}
      <div className="vv-actions">
        <Button
          disabled={pinned === 0 || (status !== undefined && !TERMINAL.has(status))}
          onClick={() => (ai ? setConfirming(true) : void start())}
        >
          {t("workflows.editor.test.run")}
        </Button>
        {status ? <StatusBadge status={status} /> : null}
      </div>
      {result ? <NodeResult result={result} runId={runId} /> : null}
      <Dialog
        open={confirming}
        title={t("workflows.editor.test.aiTitle")}
        onClose={() => setConfirming(false)}
      >
        <AiConfirmation
          workspace={workspace}
          node={node}
          pinned={pinned}
          onConfirm={() => void start()}
          onCancel={() => setConfirming(false)}
        />
      </Dialog>
    </section>
  );
}

function withoutPort(pins: Pins, port: string): Pins {
  return Object.fromEntries(Object.entries(pins).filter(([p]) => p !== port));
}

function CveSource({
  workspace,
  ports,
  onLoad,
}: {
  workspace: string;
  ports: string[];
  onLoad: (port: string, items: Item[]) => void;
}) {
  const { t } = useTranslation();
  const [shape, setShape] = useState<"event" | "summary">("event");
  const [port, setPort] = useState(ports[0] ?? "in");
  const [error, setError] = useState<string>();

  async function load(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(undefined);
    const cve = String(new FormData(event.currentTarget).get("cve") ?? "").trim();
    try {
      const sample = unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/workflow-samples/cve/{cve_id}", {
          params: { path: { workspace, cve_id: cve } },
        }),
      );
      onLoad(port, [{ json: shape === "event" ? sample.event : sample.summary }]);
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <form className="vv-form" onSubmit={load}>
      <TextField
        label={t("workflows.editor.test.cve")}
        name="cve"
        required
        pattern="[Cc][Vv][Ee]-\d{4}-\d{4,19}"
        placeholder="CVE-2026-1234"
        error={error}
      />
      <SelectField
        label={t("workflows.editor.test.shape")}
        value={shape}
        onChange={(v) => setShape(v as "event" | "summary")}
        options={[
          { value: "event", label: t("workflows.editor.test.shapes.event") },
          { value: "summary", label: t("workflows.editor.test.shapes.summary") },
        ]}
      />
      {ports.length > 1 ? (
        <SelectField
          label={t("workflows.editor.test.toPort")}
          value={port}
          onChange={setPort}
          options={ports.map((p) => ({ value: p, label: p }))}
        />
      ) : null}
      <div className="vv-actions">
        <Button type="submit" variant="secondary">
          {t("workflows.editor.test.loadCve")}
        </Button>
      </div>
    </form>
  );
}

/** Outputs of the nodes wired into this one: their last tests and real runs. */
function UpstreamSource({
  workspace,
  workflowId,
  node,
  graph,
  onLoad,
}: {
  workspace: string;
  workflowId: string;
  node: GraphNode;
  graph: Graph;
  onLoad: (port: string, items: Item[]) => void;
}) {
  const { t } = useTranslation();
  const incoming = graph.edges.filter((e) => e.to.node === node.id);
  const [edgeId, setEdgeId] = useState(incoming[0]?.id ?? "");
  const [choice, setChoice] = useState("");
  const [error, setError] = useState<string>();
  const edge = incoming.find((e) => e.id === edgeId) ?? incoming[0];
  const outputs = useQuery({
    queryKey: ["node-outputs", workspace, workflowId, edge?.from.node],
    enabled: Boolean(edge),
    queryFn: async () =>
      unwrap(
        await client.GET(
          "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/nodes/{node_id}/outputs",
          {
            params: {
              path: { workspace, workflow_id: workflowId, node_id: edge?.from.node ?? "" },
            },
          },
        ),
      ),
  });
  if (!edge) return null;
  const list = outputs.data ?? [];

  async function load() {
    if (!edge) return;
    setError(undefined);
    const runId = choice || list[0]?.run_id;
    if (!runId) return;
    try {
      const detail = unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/runs/{run_id}/nodes/{node_id}", {
          params: { path: { workspace, run_id: runId, node_id: edge.from.node } },
        }),
      );
      onLoad(edge.to.port, asItems(detail.output[edge.from.port]));
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <div className="vv-form">
      {incoming.length > 1 ? (
        <SelectField
          label={t("workflows.editor.test.upstream")}
          value={edge.id}
          onChange={(v) => {
            setEdgeId(v);
            setChoice("");
          }}
          options={incoming.map((e) => ({
            value: e.id,
            label: `${e.from.node}.${e.from.port} → ${e.to.port}`,
          }))}
        />
      ) : null}
      {list.length === 0 ? (
        <p className="vv-muted">{t("workflows.editor.test.noOutput", { node: edge.from.node })}</p>
      ) : (
        <>
          <SelectField
            label={t("workflows.editor.test.outputOf", { node: edge.from.node })}
            value={choice || list[0]?.run_id || ""}
            onChange={setChoice}
            options={list.map((o) => ({
              value: o.run_id,
              label: t(
                o.mode === "test"
                  ? "workflows.editor.test.fromTest"
                  : "workflows.editor.test.fromRun",
                {
                  at: formatDate(o.finished_at),
                  version: o.version_no ?? "?",
                  count: o.output_count,
                },
              ),
            }))}
          />
          {error ? <span className="vv-field-error">{error}</span> : null}
          <div className="vv-actions">
            <Button variant="secondary" onClick={() => void load()}>
              {t("workflows.editor.test.loadOutput")}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function AiConfirmation({
  workspace,
  node,
  pinned,
  onConfirm,
  onCancel,
}: {
  workspace: string;
  node: GraphNode;
  pinned: number;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const budget = useQuery({
    queryKey: ["ai-budget", workspace],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/ai-budget", {
          params: { path: { workspace } },
        }),
      ),
  });
  const maxItems = typeof node.params.max_items === "number" ? node.params.max_items : 10;
  const b = budget.data;
  return (
    <div className="vv-form">
      <p>{t("workflows.editor.test.aiWarning", { calls: Math.min(pinned, maxItems) })}</p>
      {b ? (
        <p>
          {b.monthly_limit_usd
            ? t("workflows.editor.test.budget", {
                spent: Number(b.spent_usd).toFixed(4),
                limit: Number(b.monthly_limit_usd).toFixed(4),
                percent: b.percent ?? 0,
              })
            : t("workflows.editor.test.noBudget", { spent: Number(b.spent_usd).toFixed(4) })}
        </p>
      ) : null}
      {b?.exhausted ? <Alert>{t("workflows.editor.test.exhausted")}</Alert> : null}
      <div className="vv-actions">
        <Button onClick={onConfirm} disabled={Boolean(b?.exhausted)}>
          {t("workflows.editor.test.aiConfirm")}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          {t("common.cancel")}
        </Button>
      </div>
    </div>
  );
}
