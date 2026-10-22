import { type Schemas, unwrap } from "@vv/api-client";
import {
  Alert,
  Button,
  Card,
  DataTable,
  PageHeader,
  SelectField,
  Tabs,
  TextArea,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { AgentStatusBadge, apiDetail, money, parseObject, rate } from "./shared";

type Case = Schemas["EvalCaseOut"];
type EvalRun = Schemas["EvalRunOut"];
type Tab = "cases" | "runs" | "compare";
type Message = { tone: "error" | "success"; text: string };

const RATES = ["schema_valid_rate", "citation_valid_rate", "refusal_rate", "accuracy"];

function metric(key: string, value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (RATES.includes(key)) return rate(Number(value));
  if (key.endsWith("_usd")) return money(value as string);
  if (key === "latency_seconds_mean") return `${Number(value).toFixed(1)} s`;
  return String(value);
}

export function EvaluationPage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const queryClient = useQueryClient();
  const workspace = slug ?? "";
  const path = { params: { path: { workspace } } };
  const [tab, setTab] = useState<Tab>("cases");
  const [message, setMessage] = useState<Message>();
  const [agentId, setAgentId] = useState("");
  const [modelId, setModelId] = useState("");
  const [baseline, setBaseline] = useState("");
  const [candidate, setCandidate] = useState("");
  const evaluator = can("ai.evaluation.run");

  const cases = useQuery({
    queryKey: ["ai-eval-cases", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/ai-evaluation/cases", path)),
  });
  const runs = useQuery({
    queryKey: ["ai-eval-runs", workspace],
    enabled: Boolean(slug),
    refetchInterval: (query) =>
      query.state.data?.some((r) => ["queued", "running"].includes(r.status)) ? 5000 : false,
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/ai-evaluation/runs", path)),
  });
  const agents = useQuery({
    queryKey: ["agents", workspace],
    enabled: Boolean(slug),
    queryFn: async () => unwrap(await client.GET("/api/v1/workspaces/{workspace}/agents", path)),
  });
  const models = useQuery({
    queryKey: ["ai-models"],
    queryFn: async () => unwrap(await client.GET("/api/v1/ai-models")),
  });
  const comparison = useQuery({
    queryKey: ["ai-eval-compare", workspace, baseline, candidate],
    enabled: Boolean(slug && baseline && candidate),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/ai-evaluation/compare", {
          params: { path: { workspace }, query: { baseline, candidate } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string, key: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: [key, workspace] });
      return true;
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
      return false;
    }
  }

  async function addCase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const expected = parseObject(String(form.get("expected") || "{}"));
    if (!expected) {
      setMessage({ tone: "error", text: t("ai.invalidJson") });
      return;
    }
    const added = await act(
      async () =>
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/ai-evaluation/cases", {
            ...path,
            body: {
              cve_id: String(form.get("cve_id")).trim().toUpperCase(),
              expected,
              notes: String(form.get("notes") ?? ""),
            },
          }),
        ),
      t("ai.eval.caseAdded"),
      "ai-eval-cases",
    );
    if (added) formElement.reset();
  }

  function removeCase(c: Case) {
    return act(
      async () =>
        unwrap(
          await client.DELETE("/api/v1/workspaces/{workspace}/ai-evaluation/cases/{case_id}", {
            params: { path: { workspace, case_id: c.id } },
          }),
        ),
      t("ai.eval.caseDeleted"),
      "ai-eval-cases",
    );
  }

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await act(
      async () =>
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/ai-evaluation/runs", {
            ...path,
            body: {
              agent_id: agentId,
              model_row_id: modelId,
              max_cost_usd: String(form.get("max_cost") || "5"),
            },
          }),
        ),
      t("ai.eval.started"),
      "ai-eval-runs",
    );
  }

  const runLabel = (r: EvalRun) => `${formatDate(r.queued_at)} · ${r.model_id}`;
  const agentName = new Map((agents.data ?? []).map((a) => [a.id, a.name]));
  const finished = (runs.data ?? []).filter((r) => r.status !== "queued" && r.status !== "running");

  return (
    <>
      <PageHeader title={t("ai.eval.title", { team: workspace.toUpperCase() })} />
      <p className="vv-muted">{t("ai.eval.intro")}</p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <Tabs<Tab>
        label={t("ai.eval.title", { team: "" })}
        value={tab}
        onChange={setTab}
        options={[
          { value: "cases", label: t("ai.eval.cases") },
          { value: "runs", label: t("ai.eval.runs") },
          { value: "compare", label: t("ai.eval.compare") },
        ]}
      />
      {tab === "cases" ? (
        <>
          <DataTable<Case>
            rows={cases.data ?? []}
            rowKey={(c) => c.id}
            empty={t("ai.eval.noCases")}
            columns={[
              { key: "cve", header: "CVE", render: (c) => c.cve_id },
              {
                key: "expected",
                header: t("ai.eval.expected"),
                render: (c) => <code>{JSON.stringify(c.expected)}</code>,
              },
              { key: "notes", header: t("ai.eval.notes"), render: (c) => c.notes || "—" },
              {
                key: "actions",
                header: "",
                render: (c) =>
                  evaluator ? (
                    <Button variant="secondary" onClick={() => void removeCase(c)}>
                      {t("ai.eval.delete")}
                    </Button>
                  ) : null,
              },
            ]}
          />
          {evaluator ? (
            <Card title={t("ai.eval.addCase")}>
              <form className="vv-form" onSubmit={addCase}>
                <TextField label="CVE" name="cve_id" required pattern="CVE-\d{4}-\d{4,19}" />
                <TextArea
                  label={t("ai.eval.expected")}
                  name="expected"
                  rows={6}
                  hint={t("ai.eval.expectedHint")}
                  defaultValue={JSON.stringify(
                    { exploitation_status: "exploited_itw", patch_status: "available" },
                    null,
                    2,
                  )}
                />
                <TextField label={t("ai.eval.notes")} name="notes" maxLength={2000} />
                <div className="vv-actions">
                  <Button type="submit">{t("ai.eval.addCase")}</Button>
                </div>
              </form>
            </Card>
          ) : null}
        </>
      ) : null}
      {tab === "runs" ? (
        <>
          <DataTable<EvalRun>
            rows={runs.data ?? []}
            rowKey={(r) => r.id}
            empty={t("ai.eval.noRuns")}
            columns={[
              { key: "date", header: t("ai.agents.date"), render: (r) => formatDate(r.queued_at) },
              {
                key: "agent",
                header: t("ai.budget.agent"),
                render: (r) => agentName.get(r.agent_id) ?? "—",
              },
              { key: "model", header: t("ai.trace.model"), render: (r) => r.model_id },
              {
                key: "status",
                header: t("workflows.state"),
                render: (r) => <AgentStatusBadge status={r.status} />,
              },
              { key: "cases", header: t("ai.eval.cases"), render: (r) => r.cases },
              {
                key: "accuracy",
                header: t("ai.eval.metrics.accuracy"),
                render: (r) => metric("accuracy", r.metrics.accuracy),
              },
              {
                key: "cost",
                header: t("ai.eval.metrics.cost_per_case_usd"),
                render: (r) => metric("cost_per_case_usd", r.metrics.cost_per_case_usd),
              },
            ]}
          />
          {evaluator ? (
            <Card title={t("ai.eval.start")}>
              <form className="vv-form" onSubmit={start}>
                <p className="vv-muted">{t("ai.eval.startHint")}</p>
                <SelectField
                  label={t("ai.budget.agent")}
                  value={agentId}
                  onChange={setAgentId}
                  options={[
                    { value: "", label: t("ai.engine.choose") },
                    ...(agents.data ?? []).map((a) => ({ value: a.id, label: a.name })),
                  ]}
                />
                <SelectField
                  label={t("ai.engine.candidate")}
                  value={modelId}
                  onChange={setModelId}
                  options={[
                    { value: "", label: t("ai.engine.choose") },
                    ...(models.data ?? [])
                      .filter((m) => m.usable)
                      .map((m) => ({ value: m.id, label: `${m.connector_name} · ${m.model_id}` })),
                  ]}
                />
                <TextField
                  label={t("ai.eval.maxCost")}
                  name="max_cost"
                  inputMode="decimal"
                  defaultValue="5"
                />
                <div className="vv-actions">
                  <Button type="submit" disabled={!agentId || !modelId}>
                    {t("ai.eval.start")}
                  </Button>
                </div>
              </form>
            </Card>
          ) : null}
        </>
      ) : null}
      {tab === "compare" ? (
        <>
          <div className="vv-filters">
            {(["baseline", "candidate"] as const).map((role) => (
              <SelectField
                key={role}
                label={t(`ai.eval.${role}`)}
                value={role === "baseline" ? baseline : candidate}
                onChange={role === "baseline" ? setBaseline : setCandidate}
                options={[
                  { value: "", label: t("ai.engine.choose") },
                  ...finished.map((r) => ({ value: r.id, label: runLabel(r) })),
                ]}
              />
            ))}
          </div>
          {comparison.data ? (
            <>
              <DataTable<[string, { baseline: unknown; candidate: unknown; delta: unknown }]>
                rows={
                  Object.entries(comparison.data.metrics) as [
                    string,
                    { baseline: unknown; candidate: unknown; delta: unknown },
                  ][]
                }
                rowKey={([key]) => key}
                empty="—"
                columns={[
                  {
                    key: "metric",
                    header: t("ai.eval.metric"),
                    render: ([key]) => t(`ai.eval.metrics.${key}`, key),
                  },
                  {
                    key: "baseline",
                    header: t("ai.eval.baseline"),
                    render: ([key, m]) => metric(key, m.baseline),
                  },
                  {
                    key: "candidate",
                    header: t("ai.eval.candidate"),
                    render: ([key, m]) => metric(key, m.candidate),
                  },
                  {
                    key: "delta",
                    header: t("ai.eval.delta"),
                    render: ([, m]) => (m.delta === null ? "—" : Number(m.delta).toFixed(3)),
                  },
                ]}
              />
              <h3>{t("ai.eval.byCase")}</h3>
              <DataTable<Record<string, unknown>>
                rows={comparison.data.cases}
                rowKey={(c) => String(c.cve_id)}
                empty="—"
                columns={[
                  { key: "cve", header: "CVE", render: (c) => String(c.cve_id) },
                  ...(["baseline", "candidate"] as const).map((role) => ({
                    key: role,
                    header: t(`ai.eval.${role}`),
                    render: (c: Record<string, unknown>) => {
                      const r = c[role] as Record<string, unknown> | null;
                      return r
                        ? `${t(`ai.status.${String(r.status)}`, String(r.status))} · ${metric("accuracy", r.accuracy)}`
                        : "—";
                    },
                  })),
                ]}
              />
            </>
          ) : (
            <p className="vv-muted">{t("ai.eval.chooseTwo")}</p>
          )}
        </>
      ) : null}
    </>
  );
}
