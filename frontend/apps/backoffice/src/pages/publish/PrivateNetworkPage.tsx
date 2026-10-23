import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage, useStepUp } from "@vv/auth";
import { Alert, Button, DataTable, Dialog, PageHeader, SelectField, TextArea } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { apiDetail } from "../ai/shared";

type Request = Schemas["PrivateNetworkRequestOut"];

/** Platform administrators decide the private ranges a team's connector may reach
 * (Q41): they see the request, never the other team's connector itself. */
export function PrivateNetworkPage() {
  const { t } = useTranslation();
  const withStepUp = useStepUp();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState("pending");
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const key = ["private-network-requests", status];
  const requests = useQuery({
    queryKey: key,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/admin/private-network-requests", {
          params: { query: { status: status || null } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await withStepUp(action);
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["private-network-requests"] });
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  const [deciding, setDeciding] = useState<{ request: Request; approve: boolean }>();
  const decide = (r: Request, approve: boolean, note: string) =>
    act(
      async () =>
        unwrap(
          await client.POST("/api/v1/admin/private-network-requests/{request_id}/decision", {
            params: { path: { request_id: r.id } },
            body: { approve, note },
          }),
        ),
      approve ? t("publish.network.approved") : t("publish.network.rejected"),
    );
  const revoke = (r: Request) =>
    act(
      async () =>
        unwrap(
          await client.POST("/api/v1/admin/private-network-requests/{request_id}/revoke", {
            params: { path: { request_id: r.id } },
            body: { note: "" },
          }),
        ),
      t("publish.network.revoked"),
    );

  return (
    <>
      <PageHeader title={t("publish.network.adminTitle")} />
      <p className="vv-muted">{t("publish.network.adminIntro")}</p>
      <div className="vv-filters">
        <SelectField
          label={t("publish.journal.status")}
          value={status}
          onChange={setStatus}
          options={["pending", "approved", "rejected", "revoked", "superseded", ""].map((s) => ({
            value: s,
            label: s ? t(`publish.network.status.${s}`) : t("common.all"),
          }))}
        />
      </div>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {requests.isError ? <Alert>{errorMessage(t, requests.error)}</Alert> : null}
      <DataTable<Request>
        rows={requests.data ?? []}
        rowKey={(r) => r.id}
        empty={requests.isPending ? t("auth.loading") : t("publish.network.empty")}
        columns={[
          {
            key: "team",
            header: t("publish.network.team"),
            render: (r) => r.workspace_slug?.toUpperCase() ?? "—",
          },
          {
            key: "connector",
            header: t("publish.network.connector"),
            render: (r) => r.connector_name,
          },
          { key: "hosts", header: t("publish.network.hosts"), render: (r) => r.hosts.join(", ") },
          { key: "cidrs", header: t("publish.network.cidrs"), render: (r) => r.cidrs.join(", ") },
          { key: "reason", header: t("publish.network.reason"), render: (r) => r.reason },
          { key: "at", header: t("publish.journal.at"), render: (r) => formatDate(r.requested_at) },
          {
            key: "status",
            header: t("publish.journal.status"),
            render: (r) => t(`publish.network.status.${r.status}`, r.status),
          },
          {
            key: "actions",
            header: "",
            render: (r) =>
              r.status === "pending" ? (
                <span className="vv-actions">
                  <Button onClick={() => setDeciding({ request: r, approve: true })}>
                    {t("publish.network.approve")}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => setDeciding({ request: r, approve: false })}
                  >
                    {t("publish.network.reject")}
                  </Button>
                </span>
              ) : r.status === "approved" ? (
                <Button variant="danger" onClick={() => void revoke(r)}>
                  {t("publish.network.revoke")}
                </Button>
              ) : null,
          },
        ]}
      />
      <Dialog
        open={Boolean(deciding)}
        title={deciding?.approve ? t("publish.network.approve") : t("publish.network.reject")}
        onClose={() => setDeciding(undefined)}
      >
        {deciding ? (
          <form
            className="vv-form"
            onSubmit={(event) => {
              event.preventDefault();
              const note = String(new FormData(event.currentTarget).get("note") ?? "");
              void decide(deciding.request, deciding.approve, note).then(() =>
                setDeciding(undefined),
              );
            }}
          >
            <p>
              {deciding.request.connector_name} · {deciding.request.cidrs.join(", ")}
            </p>
            <TextArea name="note" label={t("publish.network.note")} rows={2} maxLength={1000} />
            <Button type="submit">{t("publish.network.confirm")}</Button>
          </form>
        ) : null}
      </Dialog>
    </>
  );
}
