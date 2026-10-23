import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Card, Checkbox, PageHeader } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../api";

/** Bulletins by e-mail (Q44, Q45): each user chooses; off until they say so. */
export function NotificationsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const preferences = useQuery({
    queryKey: ["me", "notifications"],
    queryFn: async () => unwrap(await client.GET("/api/portal/v1/me/notifications")),
  });

  async function save(email_bulletins: boolean) {
    try {
      const saved = unwrap(
        await client.PUT("/api/portal/v1/me/notifications", { body: { email_bulletins } }),
      );
      queryClient.setQueryData(["me", "notifications"], saved);
      setMessage({
        tone: "success",
        text: t(saved.email_bulletins ? "notifications.on" : "notifications.off"),
      });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  return (
    <>
      <PageHeader title={t("notifications.title")} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {preferences.isError ? <Alert>{errorMessage(t, preferences.error)}</Alert> : null}
      <Card>
        {preferences.data ? (
          <Checkbox
            label={t("notifications.emailBulletins")}
            checked={preferences.data.email_bulletins}
            onChange={(checked) => void save(checked)}
          />
        ) : (
          <p className="vv-muted">{t("auth.loading")}</p>
        )}
        <p className="vv-muted">{t("notifications.explain")}</p>
      </Card>
    </>
  );
}
