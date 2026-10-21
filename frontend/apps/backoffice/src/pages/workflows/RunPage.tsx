import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, Card, DataTable, PageHeader, TextField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { duration, JsonBlock, StatusBadge, TERMINAL } from "./shared";

type NodeRun = Schemas["NodeRunOut"];

export function RunPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug, can } = useWorkspace();
  const queryClient = useQueryClient();
  const workspace = slug ?? "";
  const key = ["run", workspace, id];
  const [selected, setSelected] = useState<string>();
  const [comment, setComment] = useState("");
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const run = useQuery({
    queryKey: key,
    enabled: Boolean(slug),
    refetchInterval: (query) =>
      query.state.data && TERMINAL.has(query.state.data.status) ? false : 3000,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/runs/{run_id}", {
          params: { path: { workspace, run_id: id } },
        }),
      ),
  });
  const node = useQuery({
    queryKey: ["node-run", workspace, id, selected],
    enabled: Boolean(slug && selected),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/runs/{run_id}/nodes/{node_id}", {
          params: { path: { workspace, run_id: id, node_id: selected ?? "" } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  if (run.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (run.isError) return <Alert>{errorMessage(t, run.error)}</Alert>;
  const r = run.data;
  const pending = r.approvals.filter((a) => a.decision === null);
  const runner = can("workflow.run");

  function decide(nodeId: string, decision: "approved" | "rejected") {
    return act(
      async () =>
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/runs/{run_id}/approvals/{node_id}", {
            params: { path: { workspace, run_id: id, node_id: nodeId } },
            body: { decision, comment },
          }),
        ),
      t(`runs.decided.${decision}`),
    );
  }

  return (
    <>
      <PageHeader
        title={t("runs.title", { at: formatDate(r.queued_at) })}
        actions={
          <span className="vv-actions">
            <StatusBadge status={r.status} />
            <Link to={`/workflows/${r.workflow_id}`}>{t("runs.backToWorkflow")}</Link>
            {runner && !TERMINAL.has(r.status) && !r.cancel_requested ? (
              <Button
                variant="danger"
                onClick={() =>
                  act(
                    async () =>
                      unwrap(
                        await client.POST("/api/v1/workspaces/{workspace}/runs/{run_id}/cancel", {
                          params: { path: { workspace, run_id: id } },
                        }),
                      ),
                    t("runs.cancelRequested"),
                  )
                }
              >
                {t("runs.cancel")}
              </Button>
            ) : null}
          </span>
        }
      />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {r.error ? <Alert>{r.error}</Alert> : null}
      <dl className="vv-kv">
        <dt>{t("workflows.trigger")}</dt>
        <dd>{t(`workflows.triggerTypes.${r.trigger_type}`, r.trigger_type)}</dd>
        <dt>{t("workflows.version")}</dt>
        <dd>v{r.version_no ?? "?"}</dd>
        <dt>{t("workflows.duration")}</dt>
        <dd>{duration(r.started_at, r.finished_at)}</dd>
      </dl>
      {pending.map((a) => (
        <Card key={a.node_id} title={t("runs.approvalTitle", { node: a.node_id })}>
          <p>{t("runs.approvalHint", { at: formatDate(a.requested_at) })}</p>
          {runner ? (
            <>
              <TextField
                label={t("workflows.comment")}
                value={comment}
                maxLength={2000}
                onChange={(e) => setComment(e.target.value)}
              />
              <div className="vv-actions">
                <Button onClick={() => decide(a.node_id, "approved")}>{t("runs.approve")}</Button>
                <Button variant="danger" onClick={() => decide(a.node_id, "rejected")}>
                  {t("runs.reject")}
                </Button>
              </div>
            </>
          ) : null}
        </Card>
      ))}
      <Card title={t("runs.payload")}>
        <JsonBlock value={r.trigger_payload} />
      </Card>
      <DataTable<NodeRun>
        rows={r.node_runs}
        rowKey={(n) => `${n.node_id}:${n.attempt}`}
        empty={t("runs.noNode")}
        columns={[
          {
            key: "node",
            header: t("workflows.node"),
            render: (n) => (
              <Button variant="secondary" onClick={() => setSelected(n.node_id)}>
                {n.node_id}
              </Button>
            ),
          },
          {
            key: "status",
            header: t("workflows.state"),
            render: (n) => <StatusBadge status={n.status} />,
          },
          { key: "attempt", header: t("runs.attempt"), render: (n) => n.attempt },
          { key: "in", header: t("runs.itemsIn"), render: (n) => n.input_count },
          {
            key: "out",
            header: t("runs.itemsOut"),
            render: (n) =>
              `${n.output_count}${n.output_truncated ? ` (${t("runs.truncated")})` : ""}`,
          },
          {
            key: "duration",
            header: t("workflows.duration"),
            render: (n) => duration(n.started_at, n.finished_at),
          },
          { key: "error", header: t("workflows.error"), render: (n) => n.error ?? "" },
        ]}
      />
      {selected && node.data ? (
        <Card title={t("runs.nodeDetail", { node: selected })}>
          <p className="vv-muted">{t("runs.untrustedHint")}</p>
          <h3>{t("runs.logs")}</h3>
          <JsonBlock value={node.data.logs} />
          <h3>{t("runs.output")}</h3>
          <JsonBlock value={node.data.output} />
        </Card>
      ) : null}
    </>
  );
}
