import { ApiError, type FieldError, type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  DataTable,
  PageHeader,
  Tabs,
  TextArea,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { duration, GraphErrors, JsonBlock, StatusBadge } from "./shared";

type Detail = Schemas["WorkflowDetailOut"];
type Version = Schemas["VersionOut"];
type Run = Schemas["RunSummaryOut"];
type Trigger = Schemas["TriggerOut"];
type Secret = Schemas["WebhookSecretOut"];
type Tab = "graph" | "edit" | "versions" | "runs" | "triggers";
interface GraphNode {
  id: string;
  type: string;
  name?: string;
  params?: Record<string, unknown>;
}
interface GraphEdge {
  id: string;
  from: { node: string; port: string };
  to: { node: string; port: string };
}
interface Graph {
  nodes?: GraphNode[];
  edges?: GraphEdge[];
}

export function WorkflowPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug, can } = useWorkspace();
  const queryClient = useQueryClient();
  const workspace = slug ?? "";
  const path = { params: { path: { workspace, workflow_id: id } } };
  const [tab, setTab] = useState<Tab>("graph");
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const key = ["workflow", workspace, id];
  const detail = useQuery({
    queryKey: key,
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/workflows/{workflow_id}", path)),
  });
  const runs = useQuery({
    queryKey: ["workflow-runs", workspace, id],
    enabled: Boolean(slug) && tab === "runs",
    refetchInterval: 5000,
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/workflows/{workflow_id}/runs", path)),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
      await queryClient.invalidateQueries({ queryKey: ["workflows", workspace] });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  if (detail.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (detail.isError) return <Alert>{errorMessage(t, detail.error)}</Alert>;
  const w = detail.data;
  const editable = can("workflow.edit");
  const graph = (w.latest_graph ?? {}) as Graph;
  const manual = (graph.nodes ?? []).some((n) => n.type === "trigger.manual");

  async function activate(versionNo: number) {
    await act(
      async () => {
        const activated = unwrap(
          await client.POST(
            "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/versions/{version_no}/activate",
            { params: { path: { workspace, workflow_id: id, version_no: versionNo } } },
          ),
        );
        setSecrets(activated.webhook_secrets ?? []);
      },
      t("workflows.activated", { version: versionNo }),
    );
  }

  return (
    <>
      <PageHeader
        title={w.name}
        actions={
          <span className="vv-actions">
            <StatusBadge status={w.status} />
            {editable && w.latest_version_no && w.latest_version_no !== w.active_version_no ? (
              <Button onClick={() => activate(w.latest_version_no ?? 0)}>
                {t("workflows.activateLatest", { version: w.latest_version_no })}
              </Button>
            ) : null}
            {editable && w.active_version_no ? (
              <Button
                variant="secondary"
                onClick={() =>
                  act(
                    async () =>
                      unwrap(
                        await client.PATCH(
                          "/api/v1/workspaces/{workspace}/workflows/{workflow_id}",
                          {
                            ...path,
                            body: {
                              status: w.status === "active" ? "paused" : "active",
                              version: w.version,
                            },
                          },
                        ),
                      ),
                    t("admin.saved"),
                  )
                }
              >
                {w.status === "active" ? t("workflows.pause") : t("workflows.resume")}
              </Button>
            ) : null}
          </span>
        }
      />
      {w.description ? <p className="vv-muted">{w.description}</p> : null}
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {secrets.map((s) => (
        <Alert key={s.node_id} tone="info">
          {t("workflows.webhookSecretOnce", { node: s.node_id })} <code>{s.webhook_path}</code>{" "}
          <code>{s.secret}</code>
        </Alert>
      ))}
      {w.status === "active" && manual && can("workflow.run") ? (
        <ManualRun workspace={workspace} id={id} />
      ) : null}
      <Tabs<Tab>
        label={t("workflows.sections")}
        value={tab}
        onChange={setTab}
        options={[
          { value: "graph", label: t("workflows.graph") },
          ...(editable ? [{ value: "edit" as const, label: t("workflows.editJson") }] : []),
          { value: "versions", label: t("workflows.versions") },
          { value: "runs", label: t("workflows.runs") },
          { value: "triggers", label: t("workflows.triggers") },
        ]}
      />
      {tab === "graph" ? <GraphView graph={graph} /> : null}
      {tab === "edit" ? (
        <GraphEditor
          detail={w}
          onSaved={async (version) => {
            setMessage({ tone: "success", text: t("workflows.versionSaved", { version }) });
            await queryClient.invalidateQueries({ queryKey: key });
            setTab("versions");
          }}
        />
      ) : null}
      {tab === "versions" ? (
        <DataTable<Version>
          rows={w.versions}
          rowKey={(v) => v.id}
          empty={t("workflows.noVersion")}
          columns={[
            {
              key: "no",
              header: t("workflows.version"),
              render: (v) => (
                <>
                  v{v.version_no}{" "}
                  {v.version_no === w.active_version_no ? (
                    <Badge tone="ok">{t("workflows.status.active")}</Badge>
                  ) : null}
                </>
              ),
            },
            { key: "comment", header: t("workflows.comment"), render: (v) => v.comment || "—" },
            {
              key: "at",
              header: t("workflows.createdAt"),
              render: (v) => formatDate(v.created_at),
            },
            {
              key: "actions",
              header: "",
              render: (v) =>
                editable && v.version_no !== w.active_version_no ? (
                  <Button variant="secondary" onClick={() => activate(v.version_no)}>
                    {t("workflows.activate")}
                  </Button>
                ) : null,
            },
          ]}
        />
      ) : null}
      {tab === "runs" ? (
        <DataTable<Run>
          rows={runs.data ?? []}
          rowKey={(r) => r.id}
          empty={runs.isPending ? t("auth.loading") : t("workflows.noRun")}
          columns={[
            {
              key: "at",
              header: t("workflows.queuedAt"),
              render: (r) => <Link to={`/runs/${r.id}`}>{formatDate(r.queued_at)}</Link>,
            },
            {
              key: "status",
              header: t("workflows.state"),
              render: (r) => <StatusBadge status={r.status} />,
            },
            {
              key: "trigger",
              header: t("workflows.trigger"),
              render: (r) => t(`workflows.triggerTypes.${r.trigger_type}`, r.trigger_type),
            },
            {
              key: "version",
              header: t("workflows.version"),
              render: (r) => `v${r.version_no ?? "?"}`,
            },
            {
              key: "duration",
              header: t("workflows.duration"),
              render: (r) => duration(r.started_at, r.finished_at),
            },
            { key: "error", header: t("workflows.error"), render: (r) => r.error ?? "" },
          ]}
        />
      ) : null}
      {tab === "triggers" ? (
        <DataTable<Trigger>
          rows={w.triggers}
          rowKey={(tr) => tr.id}
          empty={t("workflows.noTrigger")}
          columns={[
            { key: "node", header: t("workflows.node"), render: (tr) => tr.node_id },
            {
              key: "type",
              header: t("workflows.trigger"),
              render: (tr) => t(`workflows.triggerTypes.${tr.type}`, tr.type),
            },
            {
              key: "detail",
              header: t("workflows.details"),
              render: (tr) =>
                tr.webhook_path ? (
                  <span className="vv-actions">
                    <code>{tr.webhook_path}</code>
                    {editable ? (
                      <Button
                        variant="secondary"
                        onClick={() =>
                          act(async () => {
                            const secret = unwrap(
                              await client.POST(
                                "/api/v1/workspaces/{workspace}/workflows/{workflow_id}/triggers/{node_id}/rotate-secret",
                                {
                                  params: {
                                    path: { workspace, workflow_id: id, node_id: tr.node_id },
                                  },
                                },
                              ),
                            );
                            setSecrets([secret]);
                          }, t("workflows.secretRotated"))
                        }
                      >
                        {t("workflows.rotateSecret")}
                      </Button>
                    ) : null}
                  </span>
                ) : tr.next_fire_at ? (
                  t("workflows.nextFire", { at: formatDate(tr.next_fire_at) })
                ) : (
                  JSON.stringify(tr.config)
                ),
            },
          ]}
        />
      ) : null}
    </>
  );
}

function GraphView({ graph }: { graph: Graph }) {
  const { t } = useTranslation();
  const nodes = graph.nodes ?? [];
  const edges = graph.edges ?? [];
  if (nodes.length === 0) return <p className="vv-muted">{t("workflows.noVersion")}</p>;
  return (
    <div className="vv-grid-2">
      {nodes.map((n) => {
        const next = edges.filter((e) => e.from.node === n.id);
        return (
          <Card key={n.id} title={n.name || n.id}>
            <dl className="vv-kv">
              <dt>{t("workflows.nodeType")}</dt>
              <dd>
                <code>{n.type}</code>
              </dd>
              <dt>{t("workflows.next")}</dt>
              <dd>
                {next.length ? next.map((e) => `${e.from.port} → ${e.to.node}`).join(", ") : "—"}
              </dd>
            </dl>
            {n.params && Object.keys(n.params).length ? <JsonBlock value={n.params} /> : null}
          </Card>
        );
      })}
    </div>
  );
}

function GraphEditor({
  detail,
  onSaved,
}: {
  detail: Detail;
  onSaved: (version: number) => Promise<void>;
}) {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const [text, setText] = useState(JSON.stringify(detail.latest_graph ?? {}, null, 2));
  const [comment, setComment] = useState("");
  const [errors, setErrors] = useState<FieldError[]>([]);
  const [error, setError] = useState<string>();

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setErrors([]);
    setError(undefined);
    let graph: Record<string, unknown>;
    try {
      graph = JSON.parse(text) as Record<string, unknown>;
    } catch {
      setError(t("workflows.invalidJson"));
      return;
    }
    try {
      const version = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/workflows/{workflow_id}/versions", {
          params: { path: { workspace: slug ?? "", workflow_id: detail.id } },
          body: { graph, comment, base_version_no: detail.latest_version_no ?? 0 },
        }),
      );
      await onSaved(version.version_no);
    } catch (err) {
      setError(errorMessage(t, err));
      if (err instanceof ApiError) setErrors(err.errors);
    }
  }

  return (
    <form className="vv-form" onSubmit={save}>
      <p className="vv-muted">{t("workflows.editHint")}</p>
      {error ? <Alert>{error}</Alert> : null}
      <GraphErrors errors={errors} />
      <TextArea
        label={t("workflows.graph")}
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={24}
        spellCheck={false}
      />
      <TextField
        label={t("workflows.comment")}
        value={comment}
        maxLength={500}
        onChange={(e) => setComment(e.target.value)}
      />
      <div className="vv-actions">
        <Button type="submit">{t("workflows.saveVersion")}</Button>
      </div>
    </form>
  );
}

function ManualRun({ workspace, id }: { workspace: string; id: string }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [input, setInput] = useState("{}");
  const [error, setError] = useState<string>();

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(input) as Record<string, unknown>;
    } catch {
      setError(t("workflows.invalidJson"));
      return;
    }
    try {
      const started = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/workflows/{workflow_id}/runs", {
          params: { path: { workspace, workflow_id: id } },
          body: { input: payload },
        }),
      );
      await navigate(`/runs/${started.run_id}`);
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <Card title={t("workflows.runNow")}>
      <form className="vv-form" onSubmit={start}>
        {error ? <Alert>{error}</Alert> : null}
        <TextArea
          label={t("workflows.input")}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={3}
          spellCheck={false}
        />
        <div className="vv-actions">
          <Button type="submit">{t("workflows.run")}</Button>
        </div>
      </form>
    </Card>
  );
}
