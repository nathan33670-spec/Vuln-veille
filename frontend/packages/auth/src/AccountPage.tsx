import type { AccountSession } from "@vv/api-client";
import { Alert, Badge, Button, Card, DataTable, PageHeader, TextField } from "@vv/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useAuthContext, useMe, useRefreshMe } from "./context";
import { errorMessage } from "./errors";
import { RecoveryCodesList } from "./pages";
import { useStepUp } from "./StepUp";

const SESSIONS_KEY = ["account", "sessions"] as const;

function formatDate(value: string): string {
  return new Date(value).toLocaleString("fr-FR");
}

function PasswordForm() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const queryClient = useQueryClient();

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setMessage({ tone: "success", text: t("account.passwordChanged") });
      await queryClient.invalidateQueries({ queryKey: SESSIONS_KEY });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  return (
    <Card title={t("account.passwordSection")}>
      <form className="vv-form" onSubmit={submit}>
        {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
        <TextField
          label={t("auth.currentPassword")}
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
        />
        <TextField
          label={t("auth.newPassword")}
          hint={t("auth.passwordHint")}
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={128}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
        />
        <div className="vv-actions">
          <Button type="submit">{t("account.change")}</Button>
        </div>
      </form>
    </Card>
  );
}

function MfaCard() {
  const { t } = useTranslation();
  const { api, appKind } = useAuthContext();
  const me = useMe().data;
  const refreshMe = useRefreshMe();
  const withStepUp = useStepUp();
  const [codes, setCodes] = useState<string[]>();
  const [error, setError] = useState<string>();
  if (!me) return null;

  async function regenerate() {
    try {
      const result = await withStepUp(() => api.regenerateRecoveryCodes());
      setCodes(result.recovery_codes);
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  async function disable() {
    try {
      await withStepUp(() => api.disableMfa());
      await refreshMe();
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <Card title={t("account.mfaSection")}>
      {error ? <Alert>{error}</Alert> : null}
      <div className="vv-actions">
        <Badge tone={me.mfa_enabled ? "ok" : "warn"}>
          {me.mfa_enabled ? t("account.mfaOn") : t("account.mfaOff")}
        </Badge>
        {me.mfa_enabled ? (
          <>
            <Button variant="secondary" onClick={regenerate}>
              {t("account.regenerate")}
            </Button>
            {appKind === "portal" ? (
              <Button variant="danger" onClick={disable}>
                {t("account.mfaDisable")}
              </Button>
            ) : null}
          </>
        ) : (
          <Link to="/mfa/enroll">{t("account.mfaEnable")}</Link>
        )}
      </div>
      {codes ? (
        <>
          <p>{t("auth.recoveryPrompt")}</p>
          <RecoveryCodesList codes={codes} />
        </>
      ) : null}
    </Card>
  );
}

function SessionsCard() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const queryClient = useQueryClient();
  const sessions = useQuery({ queryKey: SESSIONS_KEY, queryFn: () => api.listSessions() });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeSession(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: SESSIONS_KEY }),
  });

  return (
    <Card title={t("account.sessionsSection")}>
      {sessions.isError ? <Alert>{errorMessage(t, sessions.error)}</Alert> : null}
      <DataTable<AccountSession>
        rows={sessions.data ?? []}
        rowKey={(s) => s.id}
        empty={t("auth.loading")}
        columns={[
          {
            key: "created",
            header: t("account.createdAt"),
            render: (s) => formatDate(s.created_at),
          },
          { key: "seen", header: t("account.lastSeen"), render: (s) => formatDate(s.last_seen_at) },
          { key: "ip", header: t("account.ip"), render: (s) => s.ip ?? "—" },
          { key: "ua", header: t("account.device"), render: (s) => s.user_agent ?? "—" },
          {
            key: "actions",
            header: "",
            render: (s) =>
              s.current ? (
                <Badge tone="ok">{t("account.current")}</Badge>
              ) : (
                <Button variant="secondary" onClick={() => revoke.mutate(s.id)}>
                  {t("account.revoke")}
                </Button>
              ),
          },
        ]}
      />
    </Card>
  );
}

export function AccountPage() {
  const { t } = useTranslation();
  const me = useMe().data;
  return (
    <>
      <PageHeader title={t("account.title")} />
      {me ? (
        <Card title={t("account.profile")}>
          <p>
            <strong>{me.display_name}</strong> — {me.email}
          </p>
        </Card>
      ) : null}
      <PasswordForm />
      <MfaCard />
      <SessionsCard />
    </>
  );
}
