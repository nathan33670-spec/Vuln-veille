import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Badge, DataTable, PageHeader } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";

import { client } from "../../api";

export function WorkspacesPage() {
  const { t } = useTranslation();
  const workspaces = useQuery({
    queryKey: ["admin", "workspaces"],
    queryFn: async () => unwrap(await client.GET("/api/v1/admin/workspaces")),
  });
  return (
    <>
      <PageHeader title={t("admin.workspacesTitle")} />
      {workspaces.isError ? <Alert>{errorMessage(t, workspaces.error)}</Alert> : null}
      <DataTable
        rows={workspaces.data ?? []}
        rowKey={(w) => w.slug}
        empty={t("auth.loading")}
        columns={[
          { key: "name", header: t("admin.name"), render: (w) => w.name },
          { key: "members", header: t("admin.members"), render: (w) => w.member_count },
          {
            key: "admin",
            header: t("roles.platform_admin"),
            render: (w) =>
              w.grants_platform_admin ? (
                <Badge tone="ok">{t("admin.analystsAreAdmins")}</Badge>
              ) : (
                "—"
              ),
          },
        ]}
      />
    </>
  );
}
