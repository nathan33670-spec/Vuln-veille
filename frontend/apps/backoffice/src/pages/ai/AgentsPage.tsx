import { type Schemas, unwrap } from "@vv/api-client";
import { Alert, Badge, Button, DataTable, Dialog, PageHeader, TextArea, TextField } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { apiDetail, parseObject } from "./shared";

type Agent = Schemas["AgentOut"];

export const DEFAULT_SPEC = {
  engine_mode: "inherit",
  reasoning_level: "medium",
  system_prompt: "Tu es analyste de veille vulnérabilités. Réponds en français.",
  tools: ["nvd_lookup", "kev_lookup", "epss_lookup"],
  allowed_connectors: [],
  output_schema: {
    type: "object",
    properties: { summary: { type: "string" } },
    required: ["summary"],
    additionalProperties: false,
  },
  limits: { max_turns: 8, max_tool_calls: 10, max_cost_usd: "0.20" },
  data_classes: ["public", "tlp_clear"],
};

export function AgentsPage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const navigate = useNavigate();
  const workspace = slug ?? "";
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string>();
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

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const spec = parseObject(String(form.get("spec")));
    if (!spec) {
      setError(t("ai.invalidJson"));
      return;
    }
    try {
      const created = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/agents", {
          params: { path: { workspace } },
          body: {
            name: String(form.get("name")),
            description: String(form.get("description") ?? ""),
            spec: spec as Schemas["AgentSpec"],
            comment: t("ai.agents.initialVersion"),
          },
        }),
      );
      await navigate(`/agents/${created.id}`);
    } catch (err) {
      setError(apiDetail(t, err));
    }
  }

  return (
    <>
      <PageHeader
        title={t("ai.agents.title", { team: workspace.toUpperCase() })}
        actions={
          can("ai.agent.manage") ? (
            <Button onClick={() => setCreating(true)}>{t("ai.agents.create")}</Button>
          ) : null
        }
      />
      <p className="vv-muted">{t("ai.agents.intro")}</p>
      <DataTable<Agent>
        rows={agents.data ?? []}
        rowKey={(a) => a.id}
        empty={agents.isPending ? t("auth.loading") : t("ai.agents.empty")}
        columns={[
          {
            key: "name",
            header: t("admin.name"),
            render: (a) => <Link to={`/agents/${a.id}`}>{a.name}</Link>,
          },
          {
            key: "state",
            header: t("ai.agents.state"),
            render: (a) =>
              a.enabled ? (
                <Badge tone="ok">{t("ai.agents.enabled")}</Badge>
              ) : (
                <Badge>{t("ai.agents.disabled")}</Badge>
              ),
          },
          {
            key: "preset",
            header: t("ai.agents.preset"),
            render: (a) => (a.preset ? t(`ai.presets.${a.preset}`, a.preset) : "—"),
          },
          {
            key: "engine",
            header: t("ai.agents.engine"),
            render: (a) => (a.engine_mode ? t(`ai.engineMode.${a.engine_mode}`) : "—"),
          },
          {
            key: "version",
            header: t("workflows.activeVersion"),
            render: (a) => (a.active_version_no ? `v${a.active_version_no}` : "—"),
          },
          { key: "tools", header: t("ai.agents.tools"), render: (a) => a.tools.join(", ") || "—" },
          {
            key: "updated",
            header: t("ai.agents.updated"),
            render: (a) => formatDate(a.updated_at),
          },
        ]}
      />
      <Dialog open={creating} title={t("ai.agents.create")} onClose={() => setCreating(false)}>
        <form className="vv-form" onSubmit={create}>
          {error ? <Alert>{error}</Alert> : null}
          <TextField label={t("admin.name")} name="name" required maxLength={100} />
          <TextArea label={t("workflows.description")} name="description" maxLength={2000} />
          <TextArea
            label={t("ai.agents.spec")}
            name="spec"
            rows={16}
            defaultValue={JSON.stringify(DEFAULT_SPEC, null, 2)}
          />
          <div className="vv-actions">
            <Button type="submit">{t("admin.create")}</Button>
            <Button variant="secondary" type="button" onClick={() => setCreating(false)}>
              {t("auth.cancel")}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}
