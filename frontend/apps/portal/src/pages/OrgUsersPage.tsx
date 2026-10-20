import { type PortalSchemas, unwrap } from "@vv/api-client";
import { errorMessage, useMe } from "@vv/auth";
import { Alert, Badge, Button, Card, DataTable, PageHeader, SelectField, TextField } from "@vv/ui";
import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../api";

type OrgUser = PortalSchemas["OrgUserOut"];
type Role = "client_user" | "client_admin";

export function OrgUsersPage() {
  const { t } = useTranslation();
  const me = useMe().data;
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("client_user");
  const users = useInfiniteQuery({
    queryKey: ["org", "users"],
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await client.GET("/api/portal/v1/org/users", {
          params: { query: { cursor: pageParam, limit: 50 } },
        }),
      ),
    getNextPageParam: (last) => last.next_cursor,
  });
  const rows = users.data?.pages.flatMap((p) => p.items) ?? [];

  async function run(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["org", "users"] });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  async function invite(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      unwrap(
        await client.POST("/api/portal/v1/org/users", {
          body: { email, display_name: name, role },
        }),
      );
      setEmail("");
      setName("");
    }, t("org.invitationSent"));
  }

  const path = (u: OrgUser) => ({ params: { path: { user_id: u.id } } });

  return (
    <>
      <PageHeader title={t("org.title")} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {users.isError ? <Alert>{errorMessage(t, users.error)}</Alert> : null}
      <DataTable<OrgUser>
        rows={rows}
        rowKey={(u) => u.id}
        empty={users.isPending ? t("auth.loading") : t("org.noUsers")}
        columns={[
          { key: "name", header: t("org.name"), render: (u) => u.display_name },
          { key: "email", header: t("auth.email"), render: (u) => u.email },
          {
            key: "role",
            header: t("org.role"),
            render: (u) =>
              u.id === me?.id || u.status === "invited" ? (
                t(`roles.${u.role}`)
              ) : (
                <SelectField
                  label={t("org.roleOf", { name: u.display_name })}
                  value={u.role}
                  onChange={(value) =>
                    run(
                      async () =>
                        unwrap(
                          await client.PATCH("/api/portal/v1/org/users/{user_id}", {
                            ...path(u),
                            body: { role: value as Role },
                          }),
                        ),
                      t("org.saved"),
                    )
                  }
                  options={[
                    { value: "client_user", label: t("roles.client_user") },
                    { value: "client_admin", label: t("roles.client_admin") },
                  ]}
                />
              ),
          },
          {
            key: "status",
            header: t("org.status"),
            render: (u) => (
              <Badge
                tone={u.status === "active" ? "ok" : u.status === "invited" ? "warn" : "error"}
              >
                {t(`org.statuses.${u.status}`)}
              </Badge>
            ),
          },
          {
            key: "actions",
            header: "",
            render: (u) =>
              u.id === me?.id ? null : u.status === "invited" ? (
                <Button
                  variant="secondary"
                  onClick={() =>
                    run(
                      async () =>
                        unwrap(
                          await client.POST(
                            "/api/portal/v1/org/users/{user_id}/invitation",
                            path(u),
                          ),
                        ),
                      t("org.invitationSent"),
                    )
                  }
                >
                  {t("org.resend")}
                </Button>
              ) : (
                <Button
                  variant={u.status === "active" ? "danger" : "secondary"}
                  onClick={() =>
                    run(
                      async () =>
                        unwrap(
                          await client.PATCH("/api/portal/v1/org/users/{user_id}", {
                            ...path(u),
                            body: { status: u.status === "active" ? "disabled" : "active" },
                          }),
                        ),
                      t("org.saved"),
                    )
                  }
                >
                  {u.status === "active" ? t("org.disable") : t("org.enable")}
                </Button>
              ),
          },
        ]}
      />
      {users.hasNextPage ? (
        <Button variant="secondary" onClick={() => users.fetchNextPage()}>
          {t("org.more")}
        </Button>
      ) : null}
      <Card title={t("org.invite")}>
        <form className="vv-form" onSubmit={invite}>
          <TextField
            label={t("org.name")}
            value={name}
            maxLength={120}
            required
            onChange={(e) => setName(e.target.value)}
          />
          <TextField
            label={t("auth.email")}
            type="email"
            value={email}
            maxLength={254}
            required
            onChange={(e) => setEmail(e.target.value)}
          />
          <SelectField
            label={t("org.role")}
            value={role}
            onChange={(v) => setRole(v as Role)}
            options={[
              { value: "client_user", label: t("roles.client_user") },
              { value: "client_admin", label: t("roles.client_admin") },
            ]}
          />
          <div className="vv-actions">
            <Button type="submit">{t("org.sendInvitation")}</Button>
          </div>
        </form>
      </Card>
    </>
  );
}
