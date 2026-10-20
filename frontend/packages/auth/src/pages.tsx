import { setCsrfToken, type RecoveryCodes } from "@vv/api-client";
import { Alert, Button, Card, TextField } from "@vv/ui";
import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, Navigate, Outlet, useLocation, useNavigate } from "react-router";

import { ME_KEY, useAuthContext, useMe } from "./context";
import { errorMessage } from "./errors";

/** Reads the one-time token from the URL fragment, then removes it from the address bar. */
function useFragmentToken(): string | null {
  const [token] = useState(() => {
    const match = /(?:^|[#&])token=([\w-]+)/.exec(globalThis.location?.hash ?? "");
    return match?.[1] ?? null;
  });
  useEffect(() => {
    if (token) history.replaceState(null, "", location.pathname + location.search);
  }, [token]);
  return token;
}

function AuthCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="vv-auth">
      <Card title={title}>{children}</Card>
    </div>
  );
}

export function RequireAuth() {
  const { t } = useTranslation();
  const location = useLocation();
  const me = useMe();
  if (me.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (me.isError) return <Alert>{errorMessage(t, me.error)}</Alert>;
  if (!me.data) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (me.data.pending_mfa) {
    return <Navigate to={me.data.mfa_enabled ? "/mfa" : "/mfa/enroll"} replace />;
  }
  return <Outlet />;
}

export function LoginPage() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const result = await api.login(email, password);
      setCsrfToken(result.csrf_token);
      await queryClient.invalidateQueries({ queryKey: ME_KEY });
      navigate(
        result.status === "mfa_required"
          ? "/mfa"
          : result.status === "mfa_enrollment_required"
            ? "/mfa/enroll"
            : "/",
        { replace: true },
      );
    } catch (err) {
      setError(errorMessage(t, err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title={t("auth.signInTitle")}>
      <form className="vv-form" onSubmit={submit}>
        {error ? <Alert>{error}</Alert> : null}
        <TextField
          label={t("auth.email")}
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          maxLength={254}
        />
        <TextField
          label={t("auth.password")}
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          maxLength={256}
        />
        <Button type="submit" disabled={busy}>
          {t("auth.signIn")}
        </Button>
        <Link to="/forgot-password">{t("auth.forgot")}</Link>
      </form>
    </AuthCard>
  );
}

export function MfaVerifyPage() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await api.verifyMfa(code.trim());
      setCsrfToken(result.csrf_token);
      await queryClient.invalidateQueries({ queryKey: ME_KEY });
      navigate("/", { replace: true });
    } catch (err) {
      setError(errorMessage(t, err));
      setCode("");
    }
  }

  return (
    <AuthCard title={t("auth.mfaTitle")}>
      <form className="vv-form" onSubmit={submit}>
        <p>{t("auth.mfaPrompt")}</p>
        {error ? <Alert>{error}</Alert> : null}
        <TextField
          label={t("auth.code")}
          inputMode="numeric"
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          required
          maxLength={32}
          autoFocus
        />
        <Button type="submit">{t("auth.verify")}</Button>
        <Link to="/login">{t("auth.backToLogin")}</Link>
      </form>
    </AuthCard>
  );
}

export function RecoveryCodesList({ codes }: { codes: string[] }) {
  return (
    <ul className="vv-codes">
      {codes.map((c) => (
        <li key={c}>{c}</li>
      ))}
    </ul>
  );
}

export function MfaEnrollPage() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const started = useRef(false);
  const [enrollment, setEnrollment] = useState<{ secret: string; qr: string }>();
  const [codes, setCodes] = useState<RecoveryCodes>();
  const [code, setCode] = useState("");
  const [error, setError] = useState<string>();

  useEffect(() => {
    // Only once: each call replaces the pending secret on the server.
    if (started.current) return;
    started.current = true;
    api
      .startEnrollment()
      .then((e) => setEnrollment({ secret: e.secret, qr: e.qr_data_uri }))
      .catch((err: unknown) => setError(errorMessage(t, err)));
  }, [api, t]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await api.confirmEnrollment(code.trim());
      setCsrfToken(result.csrf_token);
      setCodes(result);
    } catch (err) {
      setError(errorMessage(t, err));
      setCode("");
    }
  }

  async function done() {
    await queryClient.invalidateQueries({ queryKey: ME_KEY });
    navigate("/", { replace: true });
  }

  if (codes) {
    return (
      <AuthCard title={t("auth.recoveryTitle")}>
        <p>{t("auth.recoveryPrompt")}</p>
        <RecoveryCodesList codes={codes.recovery_codes} />
        <Button onClick={done}>{t("auth.recoveryDone")}</Button>
      </AuthCard>
    );
  }

  return (
    <AuthCard title={t("auth.enrollTitle")}>
      <form className="vv-form" onSubmit={submit}>
        <p>{t("auth.enrollPrompt")}</p>
        {error ? <Alert>{error}</Alert> : null}
        {enrollment ? (
          <>
            <img className="vv-qr" src={enrollment.qr} alt="QR code" />
            <details>
              <summary>{t("auth.enrollManual")}</summary>
              <code>{enrollment.secret}</code>
            </details>
          </>
        ) : (
          <p className="vv-muted">{t("auth.loading")}</p>
        )}
        <TextField
          label={t("auth.code")}
          inputMode="numeric"
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          required
          maxLength={32}
        />
        <Button type="submit" disabled={!enrollment}>
          {t("auth.enrollConfirm")}
        </Button>
      </form>
    </AuthCard>
  );
}

function TokenPasswordPage({ kind }: { kind: "invitation" | "reset" }) {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const token = useFragmentToken();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [done, setDone] = useState(false);
  const title = kind === "invitation" ? t("auth.invitationTitle") : t("auth.resetTitle");

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    try {
      if (kind === "invitation") await api.acceptInvitation(token, password);
      else await api.resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  if (!token) {
    return (
      <AuthCard title={title}>
        <Alert>{t("auth.missingToken")}</Alert>
      </AuthCard>
    );
  }
  if (done) {
    return (
      <AuthCard title={title}>
        <Alert tone="success">
          {kind === "invitation" ? t("auth.invitationDone") : t("auth.resetDone")}
        </Alert>
        <Link to="/login">{t("auth.signIn")}</Link>
      </AuthCard>
    );
  }
  return (
    <AuthCard title={title}>
      <form className="vv-form" onSubmit={submit}>
        {error ? <Alert>{error}</Alert> : null}
        <TextField
          label={t("auth.newPassword")}
          hint={t("auth.passwordHint")}
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={128}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <Button type="submit">
          {kind === "invitation" ? t("auth.invitationSubmit") : t("auth.resetSubmit")}
        </Button>
      </form>
    </AuthCard>
  );
}

export const InvitationPage = () => <TokenPasswordPage kind="invitation" />;
export const ResetPasswordPage = () => <TokenPasswordPage kind="reset" />;

export function ForgotPasswordPage() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      await api.forgotPassword(email);
      setSent(true);
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  return (
    <AuthCard title={t("auth.forgotTitle")}>
      {sent ? (
        <Alert tone="info">{t("auth.forgotSent")}</Alert>
      ) : (
        <form className="vv-form" onSubmit={submit}>
          {error ? <Alert>{error}</Alert> : null}
          <TextField
            label={t("auth.email")}
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            maxLength={254}
          />
          <Button type="submit">{t("auth.forgotSubmit")}</Button>
        </form>
      )}
      <Link to="/login">{t("auth.backToLogin")}</Link>
    </AuthCard>
  );
}

export function SignOutButton() {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  async function signOut() {
    try {
      await api.logout();
    } finally {
      setCsrfToken(undefined);
      queryClient.clear();
      navigate("/login", { replace: true });
    }
  }
  return (
    <Button variant="secondary" onClick={signOut}>
      {t("auth.signOut")}
    </Button>
  );
}

/** Route error screen: a generic message only, never the error details or stack. */
export function RouteErrorPage() {
  const { t } = useTranslation();
  return (
    <AuthCard title={t("errors.generic")}>
      <Link to="/">{t("errors.backHome")}</Link>
    </AuthCard>
  );
}
