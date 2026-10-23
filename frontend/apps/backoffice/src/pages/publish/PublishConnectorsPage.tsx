import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Badge, Card, DataTable, PageHeader } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { client } from "../../api";
import { useWorkspace } from "../../workspace";
import { PushJournal } from "./shared";

type Target = Schemas["TargetOut"];
const HEALTH_TONE = { ok: "ok", degraded: "warn", failing: "error", unknown: "neutral" } as const;

/** The workspace's publication connectors and the global ones (Q40), with the journal. */
export function PublishConnectorsPage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const workspace = slug ?? "";
  const targets = useQuery({
    queryKey: ["publish-targets", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/publish-targets", {
          params: { path: { workspace } },
        }),
      ),
  });
  return (
    <>
      <PageHeader
        title={t("publish.list.title", { team: workspace.toUpperCase() })}
        actions={
          can("connector.publish.manage") ? (
            <Link to="/publish-connectors/new">{t("publish.list.add")}</Link>
          ) : null
        }
      />
      <p className="vv-muted">{t("publish.list.intro")}</p>
      {targets.isError ? <Alert>{errorMessage(t, targets.error)}</Alert> : null}
      <DataTable<Target>
        rows={targets.data ?? []}
        rowKey={(c) => c.id}
        empty={targets.isPending ? t("auth.loading") : t("publish.list.empty")}
        columns={[
          {
            key: "name",
            header: t("admin.name"),
            render: (c) =>
              c.scope === "workspace" && can("connector.publish.manage") ? (
                <Link to={`/publish-connectors/${c.id}`}>{c.name}</Link>
              ) : (
                c.name
              ),
          },
          {
            key: "scope",
            header: t("publish.list.scope"),
            render: (c) => t(`publish.list.scopes.${c.scope}`),
          },
          {
            key: "format",
            header: t("publish.editor.format"),
            render: (c) => (c.body_format ? t(`publish.formats.${c.body_format}`) : "—"),
          },
          {
            key: "health",
            header: t("connectors.health"),
            render: (c) => (
              <Badge tone={HEALTH_TONE[c.health as keyof typeof HEALTH_TONE] ?? "neutral"}>
                {t(`connectors.healthStates.${c.health}`)}
              </Badge>
            ),
          },
          {
            key: "enabled",
            header: t("publish.list.enabled"),
            render: (c) => (c.enabled ? t("publish.list.yes") : t("publish.list.no")),
          },
        ]}
      />
      <Card title={t("publish.journal.title")}>
        <PushJournal workspace={workspace} />
      </Card>
    </>
  );
}
