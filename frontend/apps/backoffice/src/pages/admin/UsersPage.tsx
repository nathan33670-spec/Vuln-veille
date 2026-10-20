import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  DataTable,
  Dialog,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { client } from "../../api";
import { formatDate, StatusBadge, type User } from "./shared";

export function UsersPage() {
  const { t } = useTranslation();
  const [q, setQ] = useState("");
  const [userType, setUserType] = useState("internal");
  const [inviteOpen, setInviteOpen] = useState(false);
  const users = useInfiniteQuery({
    queryKey: ["admin", "users", userType, q],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await client.GET("/api/v1/admin/users", {
          params: {
            query: { user_type: userType, q: q || null, cursor: pageParam ?? null, limit: 50 },
          },
        }),
      ),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows = users.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader
        title={t("admin.usersTitle")}
        actions={<Button onClick={() => setInviteOpen(true)}>{t("admin.invite")}</Button>}
      />
      <div className="vv-actions">
        <SelectField
          label={t("admin.userType")}
          value={userType}
          onChange={setUserType}
          options={[
            { value: "internal", label: t("admin.internal") },
            { value: "client", label: t("admin.client") },
          ]}
        />
        <TextField
          label={t("admin.search")}
          type="search"
          value={q}
          maxLength={100}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>
      {users.isError ? <Alert>{errorMessage(t, users.error)}</Alert> : null}
      <DataTable<User>
        rows={rows}
        rowKey={(u) => u.id}
        empty={users.isPending ? t("auth.loading") : t("admin.noUsers")}
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
            key: "mfa",
            header: "MFA",
            render: (u) => (
              <Badge tone={u.mfa_enabled ? "ok" : "warn"}>
                {u.mfa_enabled ? t("account.mfaOn") : t("account.mfaOff")}
              </Badge>
            ),
          },
          {
            key: "login",
            header: t("admin.lastLogin"),
            render: (u) => formatDate(u.last_login_at),
          },
        ]}
      />
      {users.hasNextPage ? (
        <Button variant="secondary" onClick={() => users.fetchNextPage()}>
          {t("admin.more")}
        </Button>
      ) : null}
      <InviteInternalDialog open={inviteOpen} onClose={() => setInviteOpen(false)} />
    </>
  );
}

function InviteInternalDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      unwrap(await client.POST("/api/v1/admin/users", { body: { email, display_name: name } }));
      setEmail("");
      setName("");
      setError(undefined);
      await queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
      onClose();
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <Dialog open={open} title={t("admin.inviteInternal")} onClose={onClose}>
      <form className="vv-form" onSubmit={submit}>
        <p className="vv-muted">{t("admin.inviteHint")}</p>
        {error ? <Alert>{error}</Alert> : null}
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
        <div className="vv-actions">
          <Button type="submit">{t("admin.sendInvitation")}</Button>
          <Button variant="secondary" onClick={onClose}>
            {t("auth.cancel")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
