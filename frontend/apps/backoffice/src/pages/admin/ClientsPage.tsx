import { unwrap } from "@vv/api-client";
import { errorMessage, useStepUp } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  DataTable,
  Dialog,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";

import { client } from "../../api";
import { formatDate, StatusBadge, type User } from "./shared";

export function ClientsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [mfa, setMfa] = useState("no");
  const [error, setError] = useState<string>();
  const clients = useQuery({
    queryKey: ["admin", "clients"],
    queryFn: async () => unwrap(await client.GET("/api/v1/admin/clients")),
  });

  async function create(event: FormEvent) {
    event.preventDefault();
    try {
      unwrap(
        await client.POST("/api/v1/admin/clients", {
          body: { name, mfa_required: mfa === "yes" },
        }),
      );
      setName("");
      setOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["admin", "clients"] });
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <>
      <PageHeader
        title={t("admin.clientsTitle")}
        actions={<Button onClick={() => setOpen(true)}>{t("admin.newClient")}</Button>}
      />
      {clients.isError ? <Alert>{errorMessage(t, clients.error)}</Alert> : null}
      <DataTable
        rows={clients.data ?? []}
        rowKey={(c) => c.id}
        empty={clients.isPending ? t("auth.loading") : t("admin.noClients")}
        columns={[
          {
            key: "name",
            header: t("admin.name"),
            render: (c) => <Link to={`/admin/clients/${c.id}`}>{c.name}</Link>,
          },
          {
            key: "status",
            header: t("admin.statusLabel"),
            render: (c) => (
              <Badge tone={c.status === "active" ? "ok" : "error"}>
                {t(`admin.status.${c.status}`)}
              </Badge>
            ),
          },
          { key: "users", header: t("admin.members"), render: (c) => c.user_count },
          {
            key: "mfa",
            header: "MFA",
            render: (c) => (c.mfa_required ? t("admin.mfaRequired") : t("admin.mfaOptional")),
          },
        ]}
      />
      <Dialog open={open} title={t("admin.newClient")} onClose={() => setOpen(false)}>
        <form className="vv-form" onSubmit={create}>
          {error ? <Alert>{error}</Alert> : null}
          <TextField
            label={t("admin.name")}
            value={name}
            maxLength={120}
            required
            onChange={(e) => setName(e.target.value)}
          />
          <SelectField
            label={t("admin.mfaPolicy")}
            value={mfa}
            onChange={setMfa}
            options={[
              { value: "no", label: t("admin.mfaOptional") },
              { value: "yes", label: t("admin.mfaRequired") },
            ]}
          />
          <div className="vv-actions">
            <Button type="submit">{t("admin.create")}</Button>
            <Button variant="secondary" onClick={() => setOpen(false)}>
              {t("auth.cancel")}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

export function ClientDetailPage() {
  const { t } = useTranslation();
  const { orgId = "" } = useParams();
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("client_admin");
  const path = { params: { path: { org_id: orgId } } };
  const org = useQuery({
    queryKey: ["admin", "client", orgId],
    queryFn: async () => unwrap(await client.GET("/api/v1/admin/clients/{org_id}", path)),
  });
  const users = useQuery({
    queryKey: ["admin", "client", orgId, "users"],
    queryFn: async () => unwrap(await client.GET("/api/v1/admin/clients/{org_id}/users", path)),
  });

  async function run(action: () => Promise<unknown>, success: string) {
    try {
      await withStepUp(action);
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["admin"] });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  async function invite(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      unwrap(
        await client.POST("/api/v1/admin/clients/{org_id}/users", {
          ...path,
          body: { email, display_name: name, role: role as "client_user" | "client_admin" },
        }),
      );
      setEmail("");
      setName("");
    }, t("admin.invitationSent"));
  }

  if (org.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (org.isError) return <Alert>{errorMessage(t, org.error)}</Alert>;
  const o = org.data;

  return (
    <>
      <PageHeader title={o.name} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <Card title={t("admin.settings")}>
        <div className="vv-actions">
          <Badge tone={o.status === "active" ? "ok" : "error"}>
            {t(`admin.status.${o.status}`)}
          </Badge>
          <Button
            variant="secondary"
            onClick={() =>
              run(
                async () =>
                  unwrap(
                    await client.PATCH("/api/v1/admin/clients/{org_id}", {
                      ...path,
                      body: { mfa_required: !o.mfa_required },
                    }),
                  ),
                t("admin.saved"),
              )
            }
          >
            {o.mfa_required ? t("admin.makeMfaOptional") : t("admin.makeMfaRequired")}
          </Button>
          <Button
            variant={o.status === "active" ? "danger" : "secondary"}
            onClick={() =>
              run(
                async () =>
                  unwrap(
                    await client.PATCH("/api/v1/admin/clients/{org_id}", {
                      ...path,
                      body: { status: o.status === "active" ? "disabled" : "active" },
                    }),
                  ),
                t("admin.saved"),
              )
            }
          >
            {o.status === "active" ? t("admin.disable") : t("admin.enable")}
          </Button>
        </div>
      </Card>
      <Card title={t("admin.clientUsers")}>
        <DataTable<User>
          rows={users.data?.items ?? []}
          rowKey={(u) => u.id}
          empty={t("admin.noUsers")}
          columns={[
            {
              key: "name",
              header: t("admin.name"),
              render: (u) => <Link to={`/admin/users/${u.id}`}>{u.display_name}</Link>,
            },
            { key: "email", header: t("auth.email"), render: (u) => u.email },
            {
              key: "status",
              header: t("admin.statusLabel"),
              render: (u) => <StatusBadge user={u} />,
            },
            {
              key: "login",
              header: t("admin.lastLogin"),
              render: (u) => formatDate(u.last_login_at),
            },
          ]}
        />
        <form className="vv-form" onSubmit={invite}>
          <h3>{t("admin.inviteClientUser")}</h3>
          <TextField
            label={t("admin.name")}
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
            label={t("admin.role")}
            value={role}
            onChange={setRole}
            options={[
              { value: "client_admin", label: t("roles.client_admin") },
              { value: "client_user", label: t("roles.client_user") },
            ]}
          />
          <div className="vv-actions">
            <Button type="submit">{t("admin.sendInvitation")}</Button>
          </div>
        </form>
      </Card>
    </>
  );
}
