import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  DataTable,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDay } from "../../lib";
import { useWorkspace } from "../../workspace";
import { apiDetail, money, rate } from "./shared";

type Model = Schemas["AIModelOut"];
type AgentCompat = Schemas["AgentCompatibilityOut"];
type Run = Schemas["AgentRunOut"];
type Message = { tone: "error" | "success"; text: string };

const LEVEL_TONE = { ok: "ok", degraded: "warn", missing: "error" } as const;

function capabilities(model: Model): Record<string, unknown> {
  return (model.verified ?? model.declared) as Record<string, unknown>;
}

/** Spending of the month by agent, from the runs (estimates; the API keeps the total). */
function byAgent(runs: Run[], names: Map<string, string>, month: string) {
  const rows = new Map<string, { name: string; runs: number; cost: number; refused: number }>();
  for (const run of runs) {
    if (!run.queued_at.startsWith(month)) continue;
    const key = run.agent_id ?? run.task ?? "—";
    const row = rows.get(key) ?? {
      name: run.agent_id ? (names.get(run.agent_id) ?? run.agent_id) : (run.task ?? "—"),
      runs: 0,
      cost: 0,
      refused: 0,
    };
    row.runs += 1;
    row.cost += Number(run.cost_estimate_usd);
    row.refused += run.status === "refused" ? 1 : 0;
    rows.set(key, row);
  }
  return [...rows.entries()].map(([key, row]) => ({ key, ...row }));
}

export function AiEnginePage() {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const queryClient = useQueryClient();
  const workspace = slug ?? "";
  const [choice, setChoice] = useState("");
  const [evaluation, setEvaluation] = useState("");
  const [hardStop, setHardStop] = useState<boolean>();
  const [message, setMessage] = useState<Message>();
  const path = { params: { path: { workspace } } };

  const models = useQuery({
    queryKey: ["ai-models"],
    queryFn: async () => unwrap(await client.GET("/api/v1/ai-models")),
  });
  const preference = useQuery({
    queryKey: ["ai-engine", workspace],
    enabled: Boolean(slug),
    queryFn: async () => unwrap(await client.GET("/api/v1/workspaces/{workspace}/ai-engine", path)),
  });
  const report = useQuery({
    queryKey: ["ai-compat", workspace, choice],
    enabled: Boolean(slug && choice),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/ai-engine/compatibility", {
          params: { path: { workspace }, query: { model_row_id: choice } },
        }),
      ),
  });
  const evaluations = useQuery({
    queryKey: ["ai-eval-runs", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/ai-evaluation/runs", path)),
  });
  const budget = useQuery({
    queryKey: ["ai-budget", workspace],
    enabled: Boolean(slug),
    queryFn: async () => unwrap(await client.GET("/api/v1/workspaces/{workspace}/ai-budget", path)),
  });
  const runs = useQuery({
    queryKey: ["agent-runs", workspace, "all"],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/agent-runs", {
          params: { path: { workspace }, query: { limit: 200 } },
        }),
      ),
  });
  const agents = useQuery({
    queryKey: ["agents", workspace],
    enabled: Boolean(slug),
    queryFn: async () => unwrap(await client.GET("/api/v1/workspaces/{workspace}/agents", path)),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["ai-engine", workspace] });
      await queryClient.invalidateQueries({ queryKey: ["ai-budget", workspace] });
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  const usable = (models.data ?? []).filter((m) => m.usable);
  const current = preference.data;
  const blocked = report.data ? !report.data.compatible : true;
  const candidates = (evaluations.data ?? []).filter(
    (e) => e.model_row_id === choice && ["succeeded", "budget_exceeded"].includes(e.status),
  );

  function apply() {
    return act(
      async () =>
        unwrap(
          await client.PUT("/api/v1/workspaces/{workspace}/ai-engine", {
            ...path,
            body: { model_row_id: choice, evaluation_id: evaluation || null },
          }),
        ),
      t("ai.engine.applied"),
    );
  }

  function inherit() {
    return act(
      async () => unwrap(await client.DELETE("/api/v1/workspaces/{workspace}/ai-engine", path)),
      t("ai.engine.inherited"),
    );
  }

  async function saveBudget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const limit = String(form.get("limit") ?? "").trim();
    await act(
      async () =>
        unwrap(
          await client.PUT("/api/v1/workspaces/{workspace}/ai-budget", {
            ...path,
            body: {
              monthly_limit_usd: limit === "" ? null : limit,
              hard_stop: hardStop ?? budget.data?.hard_stop ?? true,
            },
          }),
        ),
      t("ai.budget.saved"),
    );
  }

  const names = new Map((agents.data ?? []).map((a) => [a.id, a.name]));
  const month = budget.data?.period.slice(0, 7) ?? "";
  const spending = byAgent(runs.data ?? [], names, month);

  return (
    <>
      <PageHeader title={t("ai.engine.title", { team: workspace.toUpperCase() })} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <div className="vv-grid-2">
        <Card title={t("ai.engine.preferred")}>
          {preference.isError ? <Alert>{errorMessage(t, preference.error)}</Alert> : null}
          <dl className="vv-kv">
            <dt>{t("ai.engine.effective")}</dt>
            <dd>
              {current?.effective
                ? `${current.effective.connector_name} · ${current.effective.model_id}`
                : t("ai.engine.none")}
              {current?.source ? ` (${t(`ai.engine.source.${current.source}`)})` : ""}
            </dd>
            <dt>{t("ai.engine.platform")}</dt>
            <dd>{current?.platform ? current.platform.model_id : "—"}</dd>
          </dl>
          <SelectField
            label={t("ai.engine.candidate")}
            value={choice}
            onChange={(value) => {
              setChoice(value);
              setEvaluation("");
            }}
            options={[
              { value: "", label: t("ai.engine.choose") },
              ...usable.map((m) => ({
                value: m.id,
                label: `${m.connector_name} · ${m.model_id}`,
              })),
            ]}
          />
          {choice ? (
            <>
              <h3>{t("ai.engine.report")}</h3>
              <DataTable<AgentCompat>
                rows={report.data?.agents ?? []}
                rowKey={(a) => a.agent_id}
                empty={report.isPending ? t("auth.loading") : t("ai.engine.noAgents")}
                columns={[
                  { key: "name", header: t("admin.name"), render: (a) => a.name },
                  {
                    key: "affected",
                    header: t("ai.engine.affected"),
                    render: (a) =>
                      a.affected ? t("ai.engineMode.inherit") : t("ai.engineMode.pinned"),
                  },
                  {
                    key: "needs",
                    header: t("ai.engine.needs"),
                    render: (a) => (
                      <span className="vv-chips">
                        {a.needs.map((n) => (
                          <Badge key={n.name} tone={LEVEL_TONE[n.level]}>
                            {t(`ai.needs.${n.name}`, n.name)}
                          </Badge>
                        ))}
                      </span>
                    ),
                  },
                ]}
              />
              {report.data && !report.data.compatible ? (
                <Alert>{t("ai.engine.incompatible")}</Alert>
              ) : null}
              <SelectField
                label={t("ai.engine.evaluation")}
                value={evaluation}
                onChange={setEvaluation}
                options={[
                  { value: "", label: t("ai.engine.noEvaluation") },
                  ...candidates.map((e) => ({
                    value: e.id,
                    label: `${formatDay(e.finished_at)} · ${rate(e.metrics.accuracy as number)}`,
                  })),
                ]}
              />
              <div className="vv-actions">
                <Button disabled={blocked} onClick={() => void apply()}>
                  {t("ai.engine.apply")}
                </Button>
              </div>
            </>
          ) : null}
          {current?.workspace ? (
            <div className="vv-actions">
              <Button variant="secondary" onClick={() => void inherit()}>
                {t("ai.engine.inherit")}
              </Button>
            </div>
          ) : null}
        </Card>
        <Card title={t("ai.budget.title")}>
          {budget.data ? (
            <>
              <dl className="vv-kv">
                <dt>{t("ai.budget.spent")}</dt>
                <dd>
                  {money(budget.data.spent_usd)}
                  {budget.data.monthly_limit_usd
                    ? ` / ${money(budget.data.monthly_limit_usd)} (${budget.data.percent ?? 0} %)`
                    : ` (${t("ai.budget.noLimit")})`}
                </dd>
                <dt>{t("ai.budget.alerts")}</dt>
                <dd>
                  {budget.data.alerts_sent.length
                    ? budget.data.alerts_sent.map((a) => `${a} %`).join(", ")
                    : "—"}
                </dd>
              </dl>
              {budget.data.exhausted ? <Alert>{t("ai.budget.exhausted")}</Alert> : null}
              <form className="vv-form" onSubmit={saveBudget}>
                <TextField
                  label={t("ai.budget.limit")}
                  name="limit"
                  inputMode="decimal"
                  defaultValue={budget.data.monthly_limit_usd ?? ""}
                  hint={t("ai.budget.limitHint")}
                />
                <Checkbox
                  label={t("ai.budget.hardStop")}
                  checked={hardStop ?? budget.data.hard_stop}
                  onChange={setHardStop}
                />
                <div className="vv-actions">
                  <Button type="submit">{t("ai.budget.save")}</Button>
                </div>
              </form>
            </>
          ) : (
            <p className="vv-muted">{t("auth.loading")}</p>
          )}
        </Card>
      </div>
      <Card title={t("ai.budget.dashboard")}>
        <DataTable<(typeof spending)[number]>
          rows={spending}
          rowKey={(r) => r.key}
          empty={t("ai.budget.noRuns")}
          columns={[
            { key: "name", header: t("ai.budget.agent"), render: (r) => r.name },
            { key: "runs", header: t("ai.budget.runs"), render: (r) => r.runs },
            { key: "cost", header: t("ai.trace.cost"), render: (r) => money(r.cost) },
            {
              key: "refusals",
              header: t("ai.budget.refusals"),
              render: (r) => rate(r.runs ? r.refused / r.runs : null),
            },
          ]}
        />
        <h3>{t("ai.budget.history")}</h3>
        <DataTable<Schemas["SpendOut"]>
          rows={budget.data?.history ?? []}
          rowKey={(h) => h.period}
          empty="—"
          columns={[
            { key: "period", header: t("ai.budget.period"), render: (h) => h.period.slice(0, 7) },
            { key: "spent", header: t("ai.budget.spent"), render: (h) => money(h.spent_usd) },
            { key: "calls", header: t("ai.budget.calls"), render: (h) => h.calls },
            {
              key: "tokens",
              header: t("ai.trace.tokens"),
              render: (h) => `${h.input_tokens} / ${h.output_tokens}`,
            },
          ]}
        />
      </Card>
      <Card title={t("ai.engine.catalogue")}>
        <DataTable<Model>
          rows={models.data ?? []}
          rowKey={(m) => m.id}
          empty={models.isPending ? t("auth.loading") : t("ai.engine.noModels")}
          columns={[
            {
              key: "model",
              header: t("ai.trace.model"),
              render: (m) => `${m.connector_name} · ${m.display_name || m.model_id}`,
            },
            {
              key: "scope",
              header: t("ai.engine.scope"),
              render: (m) => t(`ai.engine.scopes.${m.scope}`),
            },
            {
              key: "caps",
              header: t("ai.engine.capabilities"),
              render: (m) => {
                const caps = capabilities(m);
                return (
                  <span className="vv-chips">
                    <Badge>{`${t("ai.needs.tools")} : ${String(caps.tools)}`}</Badge>
                    <Badge>{`JSON : ${String(caps.structured_output)}`}</Badge>
                    {caps.web_search ? <Badge>{t("ai.engine.webSearch")}</Badge> : null}
                    {m.verified ? (
                      <Badge tone="ok">{t("ai.engine.verified")}</Badge>
                    ) : (
                      <Badge tone="warn">{t("ai.engine.declared")}</Badge>
                    )}
                  </span>
                );
              },
            },
            {
              key: "data",
              header: t("ai.agents.dataClasses"),
              render: (m) => m.data_classes.join(", "),
            },
            {
              key: "price",
              header: t("ai.engine.price"),
              render: (m) =>
                m.price_input_per_mtok
                  ? `${m.price_input_per_mtok} / ${m.price_output_per_mtok ?? "—"} $`
                  : t("ai.engine.free"),
            },
            {
              key: "usable",
              header: t("ai.engine.usable"),
              render: (m) =>
                m.usable ? (
                  <Badge tone="ok">✓</Badge>
                ) : (
                  <Badge tone="error">{t("ai.engine.off")}</Badge>
                ),
            },
          ]}
        />
      </Card>
    </>
  );
}
