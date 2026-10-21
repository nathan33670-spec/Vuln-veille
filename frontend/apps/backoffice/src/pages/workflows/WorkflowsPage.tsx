import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, DataTable, Dialog, PageHeader, TextArea, TextField } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { StatusBadge } from "./shared";

type Workflow = Schemas["WorkflowOut"];

export function WorkflowsPage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const navigate = useNavigate();
  const workspace = slug ?? "";
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string>();
  const workflows = useQuery({
    queryKey: ["workflows", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/workflows", {
          params: { path: { workspace } },
        }),
      ),
  });

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const created = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/workflows", {
          params: { path: { workspace } },
          body: {
            name: String(form.get("name")),
            description: String(form.get("description") ?? ""),
            graph: {
              schema_version: 1,
              nodes: [{ id: "start", type: "trigger.manual", params: {} }],
              edges: [],
            },
            comment: t("workflows.initialVersion"),
          },
        }),
      );
      await navigate(`/workflows/${created.id}`);
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <>
      <PageHeader
        title={t("workflows.title", { team: workspace.toUpperCase() })}
        actions={
          can("workflow.edit") ? (
            <Button onClick={() => setCreating(true)}>{t("workflows.create")}</Button>
          ) : null
        }
      />
      <p className="vv-muted">{t("workflows.intro")}</p>
      <DataTable<Workflow>
        rows={workflows.data ?? []}
        rowKey={(w) => w.id}
        empty={workflows.isPending ? t("auth.loading") : t("workflows.empty")}
        columns={[
          {
            key: "name",
            header: t("admin.name"),
            render: (w) => <Link to={`/workflows/${w.id}`}>{w.name}</Link>,
          },
          {
            key: "status",
            header: t("workflows.state"),
            render: (w) => <StatusBadge status={w.status} />,
          },
          {
            key: "version",
            header: t("workflows.activeVersion"),
            render: (w) => (w.active_version_no ? `v${w.active_version_no}` : "—"),
          },
          {
            key: "last",
            header: t("workflows.lastRun"),
            render: (w) =>
              w.last_run ? (
                <Link to={`/runs/${w.last_run.id}`}>
                  <StatusBadge status={w.last_run.status} /> {formatDate(w.last_run.queued_at)}
                </Link>
              ) : (
                "—"
              ),
          },
        ]}
      />
      <Dialog open={creating} title={t("workflows.create")} onClose={() => setCreating(false)}>
        <form className="vv-form" onSubmit={create}>
          {error ? <Alert>{error}</Alert> : null}
          <TextField label={t("admin.name")} name="name" required maxLength={120} />
          <TextArea label={t("workflows.description")} name="description" maxLength={2000} />
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
