import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, DataTable, Dialog, PageHeader, SelectField, Tabs } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { DraftRequestForm } from "./DraftRequestForm";
import { type Bulletin, BulletinSeverity, BulletinStatusBadge, TlpBadge } from "./shared";

type Scope = "own" | "shared";
const STATUSES = ["", "draft", "in_review", "approved", "published", "withdrawn"];

export function BulletinsPage() {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const workspace = slug ?? "";
  const [params, setParams] = useSearchParams();
  const [scope, setScope] = useState<Scope>("own");
  const [status, setStatus] = useState("");
  // Opened from a vulnerability ("Rédiger un bulletin") or by the button below.
  const requested = params.get("vulnerability") ?? undefined;
  const [open, setOpen] = useState(Boolean(requested || params.get("cve")));
  const bulletins = useQuery({
    queryKey: ["bulletins", workspace, scope, status],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletins", {
          params: { path: { workspace }, query: { scope, status: status || null } },
        }),
      ),
  });

  function close() {
    setOpen(false);
    if (params.size) setParams({});
  }

  return (
    <>
      <PageHeader
        title={t("bulletins.title", { team: workspace.toUpperCase() })}
        actions={
          <>
            <Link to="/bulletin-templates">{t("bulletins.templatesLink")}</Link>
            <Button onClick={() => setOpen(true)}>{t("bulletins.draft.open")}</Button>
          </>
        }
      />
      <Tabs<Scope>
        label={t("bulletins.scopeLabel")}
        value={scope}
        onChange={setScope}
        options={[
          { value: "own", label: t("bulletins.scope.own") },
          { value: "shared", label: t("bulletins.scope.shared") },
        ]}
      />
      <div className="vv-filters">
        <SelectField
          label={t("bulletins.statusFilter")}
          value={status}
          onChange={setStatus}
          options={STATUSES.map((s) => ({
            value: s,
            label: s ? t(`bulletins.status.${s}`) : t("common.all"),
          }))}
        />
      </div>
      {bulletins.isError ? <Alert>{errorMessage(t, bulletins.error)}</Alert> : null}
      <DataTable<Bulletin>
        rows={bulletins.data ?? []}
        rowKey={(b) => b.id}
        empty={bulletins.isPending ? t("auth.loading") : t("bulletins.empty")}
        columns={[
          {
            key: "ref",
            header: t("bulletins.ref"),
            render: (b) => <Link to={`/bulletins/${b.id}`}>{b.ref}</Link>,
          },
          { key: "title", header: t("bulletins.titleColumn"), render: (b) => b.title },
          {
            key: "status",
            header: t("bulletins.statusColumn"),
            render: (b) => <BulletinStatusBadge status={b.status} />,
          },
          {
            key: "severity",
            header: t("bulletins.severityColumn"),
            render: (b) => <BulletinSeverity severity={b.severity} />,
          },
          { key: "tlp", header: "TLP", render: (b) => <TlpBadge tlp={b.tlp} /> },
          {
            key: "language",
            header: t("bulletins.languageColumn"),
            render: (b) => b.language.toUpperCase(),
          },
          {
            key: "updated",
            header: scope === "own" ? t("bulletins.updated") : t("bulletins.publishedAt"),
            render: (b) => formatDate(scope === "own" ? b.updated_at : b.published_at),
          },
        ]}
      />
      <Dialog open={open} title={t("bulletins.draft.title")} onClose={close}>
        <DraftRequestForm
          workspace={workspace}
          vulnerabilityId={requested}
          vulnerabilityLabel={params.get("label") ?? undefined}
          cveId={params.get("cve") ?? undefined}
        />
        <Button variant="secondary" onClick={close}>
          {t("common.cancel")}
        </Button>
      </Dialog>
    </>
  );
}
