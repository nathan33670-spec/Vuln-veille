import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Card, DataTable, ExternalLink, PageHeader } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { duration, JsonBlock } from "../workflows/shared";
import { AgentStatusBadge, FlagList, money, TERMINAL } from "./shared";

type Step = Schemas["AgentStepOut"];

/** One line per step; the full payload (collected content included) stays inert JSON. */
function stepSummary(step: Step, t: TFunction): string {
  const p = step.payload as Record<string, unknown>;
  if (step.type === "llm_call") {
    const usage = (p.usage ?? {}) as Record<string, number>;
    return t("ai.trace.llm", {
      purpose: p.purpose === "web_search" ? t("ai.trace.webSearch") : "",
      stop: String(p.stop_reason ?? ""),
      input: usage.input_tokens ?? 0,
      output: usage.output_tokens ?? 0,
      cost: money(p.cost_estimate_usd as string),
    });
  }
  if (step.type === "tool_call") return t("ai.trace.toolCall", { name: String(p.name ?? "") });
  if (step.type === "tool_result") {
    return p.error
      ? t("ai.trace.toolError", { name: String(p.name ?? ""), error: String(p.error) })
      : t("ai.trace.toolResult", {
          name: String(p.name ?? ""),
          documents: Number(p.documents ?? 0),
        });
  }
  return t("ai.trace.validation");
}

export function AgentRunPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug } = useWorkspace();
  const workspace = slug ?? "";
  const run = useQuery({
    queryKey: ["agent-run", workspace, id],
    enabled: Boolean(slug),
    refetchInterval: (query) =>
      query.state.data && TERMINAL.has(query.state.data.status) ? false : 3000,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/agent-runs/{run_id}", {
          params: { path: { workspace, run_id: id } },
        }),
      ),
  });
  if (run.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (run.isError) return <Alert>{errorMessage(t, run.error)}</Alert>;
  const r = run.data;
  const sources = r.sources.filter((s): s is string => typeof s === "string");
  return (
    <>
      <PageHeader title={t("ai.trace.title")} />
      <p>
        <AgentStatusBadge status={r.status} />{" "}
        {r.agent_id ? (
          <Link to={`/agents/${r.agent_id}`}>
            {t("ai.trace.agent", { version: r.agent_version_no ?? "?" })}
          </Link>
        ) : (
          <code>{r.task}</code>
        )}
      </p>
      {r.injection_flags.length > 0 ? (
        <Alert tone="info">{t("ai.trace.flagged", { count: r.injection_flags.length })}</Alert>
      ) : null}
      <div className="vv-grid-2">
        <Card title={t("ai.trace.engine")}>
          <dl className="vv-kv">
            <dt>{t("ai.trace.model")}</dt>
            <dd>
              {r.engine_kind ?? "—"} · {r.model_requested ?? "—"}
              {r.model_served && r.model_served !== r.model_requested ? ` → ${r.model_served}` : ""}
            </dd>
            <dt>{t("ai.trace.turns")}</dt>
            <dd>
              {r.turns} · {t("ai.trace.toolCalls", { count: r.tool_calls })}
            </dd>
            <dt>{t("ai.trace.tokens")}</dt>
            <dd>
              {r.input_tokens} / {r.output_tokens}
              {r.cache_read_tokens ? ` · cache ${r.cache_read_tokens}` : ""}
            </dd>
            <dt>{t("ai.trace.cost")}</dt>
            <dd>{money(r.cost_estimate_usd)}</dd>
            <dt>{t("ai.trace.duration")}</dt>
            <dd>
              {formatDate(r.queued_at)} · {duration(r.started_at, r.finished_at)}
            </dd>
            {r.error ? (
              <>
                <dt>{t("ai.trace.error")}</dt>
                <dd>
                  <code>{r.error}</code>
                  {r.refusal_category ? ` (${r.refusal_category})` : ""}
                </dd>
              </>
            ) : null}
          </dl>
        </Card>
        <Card title={t("ai.trace.flags")}>
          <FlagList flags={r.injection_flags} />
        </Card>
      </div>
      <Card title={t("ai.trace.output")}>
        <p className="vv-muted">{t("ai.trace.outputHint")}</p>
        {r.output ? <JsonBlock value={r.output} /> : <p className="vv-muted">—</p>}
      </Card>
      <Card title={t("ai.trace.sources")}>
        {sources.length === 0 ? (
          <p className="vv-muted">—</p>
        ) : (
          <ul className="vv-timeline">
            {sources.slice(0, 100).map((url) => (
              <li key={url}>
                <ExternalLink href={url}>{url}</ExternalLink>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title={t("ai.trace.input")}>
        <JsonBlock value={r.input} />
      </Card>
      <Card title={t("ai.trace.steps")}>
        <DataTable<Step>
          rows={r.steps}
          rowKey={(s) => String(s.seq)}
          empty="—"
          columns={[
            { key: "seq", header: "#", render: (s) => s.seq },
            { key: "type", header: t("ai.trace.type"), render: (s) => t(`ai.steps.${s.type}`) },
            { key: "summary", header: t("ai.trace.summary"), render: (s) => stepSummary(s, t) },
            {
              key: "payload",
              header: t("ai.trace.details"),
              render: (s) => (
                <details>
                  <summary>{t("ai.trace.show")}</summary>
                  <JsonBlock value={s.payload} />
                </details>
              ),
            },
          ]}
        />
      </Card>
    </>
  );
}
