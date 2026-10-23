import { unwrap } from "@vv/api-client";
import { useStepUp } from "@vv/auth";
import { Alert, Badge, Button, Card, TextArea, TextField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { apiDetail } from "../ai/shared";

type Message = { tone: "error" | "success" | "info"; text: string };
type RoutePath = "/api/v1/workspaces/{workspace}/connectors/publish/{connector_id}/private-network";

/** A connector's requests to reach private ranges (ADR-030, ADR-032): the team asks,
 * a platform administrator decides ("Réseau privé" page). */
export function PrivateNetwork({
  family,
  workspace,
  connectorId,
}: {
  family: "publish" | "ai_engine";
  workspace: string;
  connectorId: string;
}) {
  const { t } = useTranslation();
  const withStepUp = useStepUp();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<Message>();
  const path = { workspace, connector_id: connectorId };
  const key = ["private-network", workspace, connectorId];
  // Both families share the schemas: the typed path is the publication one.
  const route =
    `/api/v1/workspaces/{workspace}/connectors/${family}/{connector_id}/private-network` as RoutePath;
  const requests = useQuery({
    queryKey: key,
    queryFn: async () => unwrap(await client.GET(route, { params: { path } })),
  });

  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await withStepUp(async () =>
        unwrap(
          await client.POST(route, {
            params: { path },
            body: {
              cidrs: String(form.get("cidrs") ?? "")
                .split(/[\s,]+/)
                .filter(Boolean),
              reason: String(form.get("reason") ?? ""),
            },
          }),
        ),
      );
      setMessage({ tone: "success", text: t("publish.network.requested") });
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <Card title={t("publish.network.title")}>
      <p className="vv-muted">{t("publish.network.hint")}</p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <ul className="vv-change-list">
        {(requests.data ?? []).map((r) => (
          <li key={r.id}>
            <Badge
              tone={r.status === "approved" ? "ok" : r.status === "pending" ? "warn" : "neutral"}
            >
              {t(`publish.network.status.${r.status}`, r.status)}
            </Badge>{" "}
            {r.cidrs.join(", ")} · {formatDate(r.requested_at)} · {r.reason}
            {r.decision_note ? ` · ${r.decision_note}` : ""}
          </li>
        ))}
      </ul>
      <form className="vv-form" onSubmit={request}>
        <TextField
          name="cidrs"
          label={t("publish.network.cidrs")}
          placeholder="10.20.0.0/16"
          required
        />
        <TextArea
          name="reason"
          label={t("publish.network.reason")}
          rows={2}
          required
          maxLength={1000}
        />
        <Button type="submit" variant="secondary">
          {t("publish.network.submit")}
        </Button>
      </form>
    </Card>
  );
}
