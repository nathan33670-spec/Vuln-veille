import { unwrap } from "@vv/api-client";
import { errorMessage, useMe, useStepUp } from "@vv/auth";
import { Alert, Badge, Button, Card, PageHeader, SelectField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router";

import { client } from "../../api";
import { formatDate, StatusBadge } from "./shared";

const WORKSPACES = ["voc", "cert"] as const;

export function UserDetailPage() {
  const { t } = useTranslation();
  const { userId = "" } = useParams();
  const me = useMe().data;
  const withStepUp = useStepUp();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const key = ["admin", "user", userId];
  const user = useQuery({
    queryKey: key,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/admin/users/{user_id}", {
          params: { path: { user_id: userId } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await withStepUp(action);
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["admin"] });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  if (user.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (user.isError) return <Alert>{errorMessage(t, user.error)}</Alert>;
  const u = user.data;
  const path = { params: { path: { user_id: u.id } } };
  const isSelf = me?.id === u.id;

  return (
    <>
      <PageHeader title={u.display_name} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <Card title={t("admin.account")}>
        <p>{u.email}</p>
        <div className="vv-actions">
          <StatusBadge user={u} />
          <Badge tone={u.mfa_enabled ? "ok" : "warn"}>
            MFA {u.mfa_enabled ? t("account.mfaOn") : t("account.mfaOff")}
          </Badge>
          <span className="vv-muted">
            {t("admin.lastLogin")} : {formatDate(u.last_login_at)}
          </span>
        </div>
        <div className="vv-actions">
          {u.status === "invited" ? (
            <Button
              variant="secondary"
              onClick={() =>
                act(
                  async () =>
                    unwrap(await client.POST("/api/v1/admin/users/{user_id}/invitation", path)),
                  t("admin.invitationSent"),
                )
              }
            >
              {t("admin.resendInvitation")}
            </Button>
          ) : null}
          {!isSelf && u.status !== "invited" ? (
            <Button
              variant={u.status === "active" ? "danger" : "secondary"}
              onClick={() =>
                act(
                  async () =>
                    unwrap(
                      await client.PATCH("/api/v1/admin/users/{user_id}", {
                        ...path,
                        body: { status: u.status === "active" ? "disabled" : "active" },
                      }),
                    ),
                  t("admin.saved"),
                )
              }
            >
              {u.status === "active" ? t("admin.disable") : t("admin.enable")}
            </Button>
          ) : null}
          {u.locked ? (
            <Button
              variant="secondary"
              onClick={() =>
                act(
                  async () =>
                    unwrap(await client.POST("/api/v1/admin/users/{user_id}/unlock", path)),
                  t("admin.saved"),
                )
              }
            >
              {t("admin.unlock")}
            </Button>
          ) : null}
          {u.mfa_enabled ? (
            <Button
              variant="secondary"
              onClick={() =>
                act(
                  async () =>
                    unwrap(await client.POST("/api/v1/admin/users/{user_id}/mfa/reset", path)),
                  t("admin.mfaResetDone"),
                )
              }
            >
              {t("admin.resetMfa")}
            </Button>
          ) : null}
          <Button
            variant="secondary"
            onClick={() =>
              act(
                async () =>
                  unwrap(await client.DELETE("/api/v1/admin/users/{user_id}/sessions", path)),
                t("admin.sessionsRevoked"),
              )
            }
          >
            {t("admin.revokeSessions")}
          </Button>
        </div>
      </Card>

      {u.user_type === "internal" ? (
        <Card title={t("admin.access")}>
          <p className="vv-muted">{t("admin.accessHint")}</p>
          {WORKSPACES.map((slug) => {
            const membership = u.workspaces.find((w) => w.slug === slug);
            return (
              <div key={slug} className="vv-actions">
                <SelectField
                  label={t(`workspaces.${slug}`)}
                  value={membership?.role ?? "none"}
                  onChange={(role) =>
                    act(async () => {
                      const params = { params: { path: { user_id: u.id, workspace: slug } } };
                      if (role === "none") {
                        unwrap(
                          await client.DELETE(
                            "/api/v1/admin/users/{user_id}/workspaces/{workspace}",
                            params,
                          ),
                        );
                      } else {
                        unwrap(
                          await client.PUT("/api/v1/admin/users/{user_id}/workspaces/{workspace}", {
                            ...params,
                            body: { role: role as "analyst" | "viewer" },
                          }),
                        );
                      }
                    }, t("admin.saved"))
                  }
                  options={[
                    { value: "none", label: t("roles.none") },
                    { value: "analyst", label: t("roles.analyst") },
                    { value: "viewer", label: t("roles.viewer") },
                  ]}
                />
              </div>
            );
          })}
          <div className="vv-actions">
            <Badge tone={u.global_roles.includes("platform_admin") ? "ok" : "neutral"}>
              {t("roles.platform_admin")}
            </Badge>
            <Button
              variant="secondary"
              onClick={() =>
                act(async () => {
                  const params = { params: { path: { user_id: u.id, role: "platform_admin" } } };
                  if (u.global_roles.includes("platform_admin")) {
                    unwrap(
                      await client.DELETE(
                        "/api/v1/admin/users/{user_id}/global-roles/{role}",
                        params,
                      ),
                    );
                  } else {
                    unwrap(
                      await client.PUT("/api/v1/admin/users/{user_id}/global-roles/{role}", params),
                    );
                  }
                }, t("admin.saved"))
              }
            >
              {u.global_roles.includes("platform_admin")
                ? t("admin.revokeRole")
                : t("admin.grantRole")}
            </Button>
          </div>
        </Card>
      ) : u.client_org ? (
        <Card title={t("admin.organization")}>
          <p>
            {u.client_org.name} — {t(`roles.${u.client_org.role}`)}
          </p>
        </Card>
      ) : null}
    </>
  );
}
