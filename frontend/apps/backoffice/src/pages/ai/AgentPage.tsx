import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Badge, Button, Card, DataTable, PageHeader, TextArea, TextField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { AgentStatusBadge, apiDetail, money, parseObject } from "./shared";

type Version = Schemas["AgentVersionOut"];
type Run = Schemas["AgentRunOut"];
type Message = { tone: "error" | "success"; text: string };

function SpecSummary({ spec }: { spec: Record<string, unknown> }) {
  const { t } = useTranslation();
  const limits = (spec.limits ?? {}) as Record<string, unknown>;
  const list = (value: unknown) => (Array.isArray(value) && value.length ? value.join(", ") : "—");
  return (
    <>
      <dl className="vv-kv">
        <dt>{t("ai.agents.engine")}</dt>
        <dd>
          {t(`ai.engineMode.${String(spec.engine_mode ?? "inherit")}`)}
          {spec.engine_model_row_id ? ` (${String(spec.engine_model_row_id)})` : ""}
        </dd>
        <dt>{t("ai.agents.reasoning")}</dt>
        <dd>{String(spec.reasoning_level ?? "medium")}</dd>
        <dt>{t("ai.agents.tools")}</dt>
        <dd>{list(spec.tools)}</dd>
        <dt>{t("ai.agents.connectors")}</dt>
        <dd>{Array.isArray(spec.allowed_connectors) ? spec.allowed_connectors.length : 0}</dd>
        <dt>{t("ai.agents.dataClasses")}</dt>
        <dd>{list(spec.data_classes)}</dd>
        <dt>{t("ai.agents.limits")}</dt>
        <dd>
          {t("ai.agents.limitsValue", {
            turns: limits.max_turns ?? "—",
            tools: limits.max_tool_calls ?? "—",
            cost: money(limits.max_cost_usd as string),
          })}
        </dd>
      </dl>
      <h3>{t("ai.agents.prompt")}</h3>
      <pre className="vv-pre">{String(spec.system_prompt ?? "")}</pre>
    </>
  );
}

export function AgentPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug, can } = useWorkspace();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const workspace = slug ?? "";
  const key = ["agent", workspace, id];
  const [message, setMessage] = useState<Message>();
  const [editing, setEditing] = useState(false);
  const agent = useQuery({
    queryKey: key,
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/agents/{agent_id}", {
          params: { path: { workspace, agent_id: id } },
        }),
      ),
  });
  const runs = useQuery({
    queryKey: ["agent-runs", workspace, id],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/agent-runs", {
          params: { path: { workspace }, query: { agent_id: id, limit: 20 } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
      await queryClient.invalidateQueries({ queryKey: ["agent-runs", workspace, id] });
      return true;
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
      return false;
    }
  }

  if (agent.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (agent.isError) return <Alert>{errorMessage(t, agent.error)}</Alert>;
  const a = agent.data;
  const manager = can("ai.agent.manage");
  const path = { workspace, agent_id: id };

  function toggle() {
    return act(
      async () =>
        unwrap(
          await client.PATCH("/api/v1/workspaces/{workspace}/agents/{agent_id}", {
            params: { path },
            body: { enabled: !a.enabled, version: a.version },
          }),
        ),
      a.enabled ? t("ai.agents.disabledDone") : t("ai.agents.enabledDone"),
    );
  }

  async function saveVersion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const spec = parseObject(String(form.get("spec")));
    if (!spec) {
      setMessage({ tone: "error", text: t("ai.invalidJson") });
      return;
    }
    const saved = await act(
      async () =>
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/agents/{agent_id}/versions", {
            params: { path },
            body: {
              spec: spec as Schemas["AgentSpec"],
              comment: String(form.get("comment") ?? ""),
              base_version_no: a.versions[0]?.version_no ?? null,
            },
          }),
        ),
      t("ai.agents.versionSaved"),
    );
    if (saved) setEditing(false);
  }

  function activate(version: Version) {
    return act(
      async () =>
        unwrap(
          await client.POST(
            "/api/v1/workspaces/{workspace}/agents/{agent_id}/versions/{version_no}/activate",
            { params: { path: { ...path, version_no: version.version_no } } },
          ),
        ),
      t("ai.agents.activated", { version: version.version_no }),
    );
  }

  async function test(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const input = parseObject(String(form.get("input")));
    if (!input) {
      setMessage({ tone: "error", text: t("ai.invalidJson") });
      return;
    }
    try {
      const queued = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/agents/{agent_id}/test", {
          params: { path },
          body: { input },
        }),
      );
      await navigate(`/agent-runs/${queued.run_id}`);
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <>
      <PageHeader
        title={a.name}
        actions={
          manager ? (
            <>
              <Button variant="secondary" onClick={() => void toggle()}>
                {a.enabled ? t("ai.agents.disable") : t("ai.agents.enable")}
              </Button>
              <Button onClick={() => setEditing((v) => !v)}>{t("ai.agents.edit")}</Button>
            </>
          ) : null
        }
      />
      <p>
        {a.enabled ? (
          <Badge tone="ok">{t("ai.agents.enabled")}</Badge>
        ) : (
          <Badge>{t("ai.agents.disabled")}</Badge>
        )}{" "}
        {a.preset ? <Badge>{t(`ai.presets.${a.preset}`, a.preset)}</Badge> : null}{" "}
        <span className="vv-muted">{a.description}</span>
      </p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {!a.enabled ? <Alert tone="info">{t("ai.agents.disabledHint")}</Alert> : null}
      {editing && a.active_spec ? (
        <Card title={t("ai.agents.newVersion")}>
          <form className="vv-form" onSubmit={saveVersion}>
            <p className="vv-muted">{t("ai.agents.specHint")}</p>
            <TextArea
              label={t("ai.agents.spec")}
              name="spec"
              rows={24}
              defaultValue={JSON.stringify(a.active_spec, null, 2)}
            />
            <TextField label={t("workflows.comment")} name="comment" maxLength={500} />
            <div className="vv-actions">
              <Button type="submit">{t("ai.agents.saveVersion")}</Button>
            </div>
          </form>
        </Card>
      ) : null}
      <div className="vv-grid-2">
        <Card title={t("ai.agents.activeSpec", { version: a.active_version_no ?? "—" })}>
          {a.active_spec ? <SpecSummary spec={a.active_spec} /> : <p>—</p>}
        </Card>
        <Card title={t("ai.agents.sandbox")}>
          {can("ai.agent.run") ? (
            <form className="vv-form" onSubmit={test}>
              <p className="vv-muted">{t("ai.agents.sandboxHint")}</p>
              <TextArea
                label={t("ai.agents.input")}
                name="input"
                rows={6}
                defaultValue={JSON.stringify({ cve_id: "CVE-2026-" }, null, 2)}
              />
              <div className="vv-actions">
                <Button type="submit">{t("ai.agents.runTest")}</Button>
              </div>
            </form>
          ) : (
            <p className="vv-muted">{t("errors.forbidden")}</p>
          )}
        </Card>
      </div>
      <Card title={t("ai.agents.runs")}>
        <DataTable<Run>
          rows={runs.data ?? []}
          rowKey={(r) => r.id}
          empty={t("ai.agents.noRuns")}
          columns={[
            {
              key: "date",
              header: t("ai.agents.date"),
              render: (r) => <Link to={`/agent-runs/${r.id}`}>{formatDate(r.queued_at)}</Link>,
            },
            {
              key: "status",
              header: t("workflows.state"),
              render: (r) => <AgentStatusBadge status={r.status} />,
            },
            {
              key: "context",
              header: t("ai.agents.context"),
              render: (r) => t(`ai.context.${r.context_type}`),
            },
            {
              key: "model",
              header: t("ai.trace.model"),
              render: (r) => r.model_served ?? r.model_requested ?? "—",
            },
            { key: "cost", header: t("ai.trace.cost"), render: (r) => money(r.cost_estimate_usd) },
            {
              key: "flags",
              header: t("ai.trace.flags"),
              render: (r) =>
                r.injection_flag_count ? <Badge tone="warn">{r.injection_flag_count}</Badge> : "—",
            },
          ]}
        />
      </Card>
      <Card title={t("workflows.versions")}>
        <DataTable<Version>
          rows={a.versions}
          rowKey={(v) => v.id}
          empty="—"
          columns={[
            { key: "no", header: "#", render: (v) => `v${v.version_no}` },
            { key: "date", header: t("ai.agents.date"), render: (v) => formatDate(v.created_at) },
            { key: "comment", header: t("workflows.comment"), render: (v) => v.comment || "—" },
            {
              key: "actions",
              header: "",
              render: (v) =>
                v.version_no === a.active_version_no ? (
                  <Badge tone="ok">{t("ai.agents.active")}</Badge>
                ) : manager ? (
                  <Button variant="secondary" onClick={() => void activate(v)}>
                    {t("ai.agents.activate")}
                  </Button>
                ) : null,
            },
          ]}
        />
      </Card>
    </>
  );
}
