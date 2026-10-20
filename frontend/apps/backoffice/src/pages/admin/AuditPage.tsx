import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Badge, Button, DataTable, PageHeader, SelectField, TextField } from "@vv/ui";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "./shared";

type AuditEvent = Schemas["AuditEventOut"];

export function AuditPage() {
  const { t } = useTranslation();
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const filter = /^[a-z][a-z0-9_.]*$/.test(action) ? action : null;
  const events = useInfiniteQuery({
    queryKey: ["admin", "audit", filter, outcome],
    initialPageParam: undefined as number | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await client.GET("/api/v1/admin/audit", {
          params: {
            query: {
              action: filter,
              outcome: outcome || null,
              before_id: pageParam ?? null,
              limit: 100,
            },
          },
        }),
      ),
    getNextPageParam: (last) => last.next_before_id ?? undefined,
  });
  const verify = useQuery({
    queryKey: ["admin", "audit", "verify"],
    queryFn: async () => unwrap(await client.GET("/api/v1/admin/audit/verify")),
    enabled: false,
  });
  const rows = events.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader
        title={t("admin.auditTitle")}
        actions={
          <>
            <Button variant="secondary" onClick={() => verify.refetch()}>
              {t("admin.verifyChain")}
            </Button>
            <a className="vv-button vv-button-secondary" href="/api/v1/admin/audit/export" download>
              {t("admin.export")}
            </a>
          </>
        }
      />
      {verify.data ? (
        <Alert tone={verify.data.intact ? "success" : "error"}>
          {verify.data.intact
            ? t("admin.chainIntact")
            : t("admin.chainBroken", { id: verify.data.first_broken_id })}
        </Alert>
      ) : null}
      <div className="vv-actions">
        <TextField
          label={t("admin.action")}
          value={action}
          maxLength={80}
          placeholder="auth.login"
          onChange={(e) => setAction(e.target.value.trim())}
        />
        <SelectField
          label={t("admin.outcome")}
          value={outcome}
          onChange={setOutcome}
          options={[
            { value: "", label: t("admin.all") },
            { value: "success", label: "success" },
            { value: "failure", label: "failure" },
            { value: "denied", label: "denied" },
          ]}
        />
      </div>
      {events.isError ? <Alert>{errorMessage(t, events.error)}</Alert> : null}
      <DataTable<AuditEvent>
        rows={rows}
        rowKey={(e) => String(e.id)}
        empty={events.isPending ? t("auth.loading") : t("admin.noEvents")}
        columns={[
          { key: "at", header: t("admin.when"), render: (e) => formatDate(e.occurred_at) },
          { key: "action", header: t("admin.action"), render: (e) => <code>{e.action}</code> },
          {
            key: "outcome",
            header: t("admin.outcome"),
            render: (e) => (
              <Badge tone={e.outcome === "success" ? "ok" : "error"}>{e.outcome}</Badge>
            ),
          },
          {
            key: "actor",
            header: t("admin.actor"),
            render: (e) => e.actor_user_id ?? e.actor_type,
          },
          {
            key: "target",
            header: t("admin.target"),
            render: (e) => (e.target_type ? `${e.target_type}:${e.target_id ?? ""}` : "—"),
          },
          { key: "ip", header: t("account.ip"), render: (e) => e.ip ?? "—" },
          {
            key: "details",
            header: t("admin.details"),
            render: (e) => <code>{JSON.stringify(e.details)}</code>,
          },
        ]}
      />
      {events.hasNextPage ? (
        <Button variant="secondary" onClick={() => events.fetchNextPage()}>
          {t("admin.more")}
        </Button>
      ) : null}
    </>
  );
}
