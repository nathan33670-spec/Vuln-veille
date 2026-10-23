import { type Schemas, unwrap } from "@vv/api-client";
import { Badge, DataTable } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "../../lib";

export type Push = Schemas["PushOut"];
export type PushDetail = Schemas["PushDetailOut"];

export const AUTH_TYPES = [
  "none",
  "api_key",
  "bearer",
  "basic",
  "oauth2_client_credentials",
  "mtls",
  "hmac",
] as const;
export type AuthType = (typeof AUTH_TYPES)[number];

/** Secret slots each authentication type needs (mirrors the server, ADR-030). */
export const REQUIRED_SLOTS: Record<AuthType, string[]> = {
  none: [],
  api_key: ["credential"],
  bearer: ["credential"],
  basic: ["username", "password"],
  oauth2_client_credentials: ["client_id", "client_secret"],
  mtls: ["client_certificate", "client_key"],
  hmac: ["signing_key"],
};

export interface PublishConfig {
  request: {
    base_url: string;
    method: "POST" | "PUT" | "PATCH";
    path: string;
    update: { method: "POST" | "PUT" | "PATCH"; path: string } | null;
    headers: Record<string, string>;
    timeout_seconds: number;
    health_path: string;
  };
  auth: {
    type: AuthType;
    key_location: "header" | "query";
    key_name: string;
    endpoint_url: string | null;
    scope: string;
    audience: string;
    algorithm: "sha256" | "sha512";
    signed_header: string;
    digest_prefix: string;
    encoding: "hex" | "base64";
    timestamp_header: string;
  };
  body: { format: "json" | "csaf" | "markdown"; mapping: unknown };
  response: { success_status: number[]; remote_id_path: string };
  idempotency_header: string;
  retry: {
    max_attempts: number;
    backoff_seconds: number[];
    retry_on: number[];
    retry_network: boolean;
  };
  rate_limit_per_minute: number;
}

export const EXAMPLE_MAPPING = {
  title: { path: "bulletin.title" },
  reference: { path: "bulletin.ref" },
  severity: {
    path: "bulletin.severity",
    map: { critical: "P1", high: "P2", medium: "P3", low: "P4" },
  },
  cves: { path: "cves" },
  content: { path: "revision.markdown" },
  published: { path: "bulletin.published_at", format: "iso8601" },
  source: { const: "Vuln-Veille" },
};

export function defaultConfig(): PublishConfig {
  return {
    request: {
      base_url: "https://",
      method: "POST",
      path: "/",
      update: null,
      headers: {},
      timeout_seconds: 20,
      health_path: "",
    },
    auth: {
      type: "bearer",
      key_location: "header",
      key_name: "X-API-Key",
      endpoint_url: null,
      scope: "",
      audience: "",
      algorithm: "sha256",
      signed_header: "X-Signature",
      digest_prefix: "sha256=",
      encoding: "hex",
      timestamp_header: "",
    },
    body: { format: "json", mapping: EXAMPLE_MAPPING },
    response: { success_status: [200, 201, 202, 204], remote_id_path: "" },
    idempotency_header: "Idempotency-Key",
    retry: {
      max_attempts: 5,
      backoff_seconds: [10, 30, 120, 600, 1800],
      retry_on: [429, 500, 502, 503, 504],
      retry_network: true,
    },
    rate_limit_per_minute: 30,
  };
}

/** A stored configuration completed with the defaults (older or partial ones). */
export function withDefaults(raw: Record<string, unknown> | undefined): PublishConfig {
  const base = defaultConfig();
  const value = (raw ?? {}) as Partial<PublishConfig>;
  return {
    ...base,
    ...value,
    request: { ...base.request, ...(value.request ?? {}) },
    auth: { ...base.auth, ...(value.auth ?? {}) },
    body: { ...base.body, ...(value.body ?? {}) },
    response: { ...base.response, ...(value.response ?? {}) },
    retry: { ...base.retry, ...(value.retry ?? {}) },
  };
}

/** "200, 201" -> [200, 201]; invalid entries dropped. */
export function numbers(text: string): number[] {
  return text
    .split(",")
    .map((v) => Number(v.trim()))
    .filter((v) => Number.isInteger(v) && v > 0);
}

const STATUS_TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  queued: "neutral",
  sending: "warn",
  retrying: "warn",
  succeeded: "ok",
  failed: "error",
};

export function PushStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <Badge tone={STATUS_TONE[status] ?? "neutral"}>{t(`publish.status.${status}`, status)}</Badge>
  );
}

export const PUSH_TERMINAL = new Set(["succeeded", "failed"]);
const POLL_MS = 1500;

/** Polls a push until it ends (or while it waits for a retry, every few seconds). */
export function usePush(workspace: string, id: string | undefined) {
  const [push, setPush] = useState<PushDetail>();
  useEffect(() => {
    if (!id) return;
    let stopped = false;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const value = unwrap(
          await client.GET("/api/v1/workspaces/{workspace}/publications/{publication_id}", {
            params: { path: { workspace, publication_id: id } },
          }),
        );
        if (stopped) return;
        setPush(value);
        if (PUSH_TERMINAL.has(value.status)) return;
      } catch {
        // transient: the next tick retries
      }
      if (!stopped) timer = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [workspace, id]);
  return push;
}

/** The pushes of a bulletin or a connector, newest first, each with its attempts. */
export function PushJournal({
  workspace,
  bulletinId,
  connectorId,
}: {
  workspace: string;
  bulletinId?: string;
  connectorId?: string;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<string>();
  const pushes = useQuery({
    queryKey: ["publications", workspace, bulletinId ?? null, connectorId ?? null],
    refetchInterval: 5000,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/publications", {
          params: {
            path: { workspace },
            query: { bulletin_id: bulletinId ?? null, connector_id: connectorId ?? null },
          },
        }),
      ),
  });
  return (
    <>
      <DataTable<Push>
        rows={pushes.data ?? []}
        rowKey={(p) => p.id}
        empty={pushes.isPending ? t("auth.loading") : t("publish.journal.empty")}
        columns={[
          { key: "at", header: t("publish.journal.at"), render: (p) => formatDate(p.created_at) },
          {
            key: "what",
            header: t("publish.journal.what"),
            render: (p) =>
              p.is_test
                ? t("publish.journal.test")
                : `${p.bulletin_ref ?? "—"}${p.rev_no ? ` r${p.rev_no}` : ""}`,
          },
          { key: "target", header: t("publish.journal.target"), render: (p) => p.connector_name },
          {
            key: "status",
            header: t("publish.journal.status"),
            render: (p) => <PushStatusBadge status={p.status} />,
          },
          {
            key: "detail",
            header: t("publish.journal.detail"),
            render: (p) =>
              [
                p.mode ? t(`publish.mode.${p.mode}`) : null,
                p.response_status ? `HTTP ${p.response_status}` : null,
                p.remote_id ? t("publish.journal.remote", { id: p.remote_id }) : null,
                p.error,
                t("publish.journal.attempts", { count: p.attempts }),
              ]
                .filter(Boolean)
                .join(" · "),
          },
          {
            key: "open",
            header: "",
            render: (p) => (
              <button
                type="button"
                className="vv-link-button"
                onClick={() => setOpen(open === p.id ? undefined : p.id)}
              >
                {open === p.id ? t("publish.journal.hide") : t("publish.journal.show")}
              </button>
            ),
          },
        ]}
      />
      {open ? <Attempts workspace={workspace} id={open} /> : null}
    </>
  );
}

/** A journalled request as text: method and URL, headers, then the body (formatted
 * when it is JSON). Credentials are already masked by the server. */
export function requestText(request: Record<string, unknown>): string {
  const headers = Object.entries((request.headers ?? {}) as Record<string, string>)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
  let body = String(request.body ?? "");
  try {
    body = JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    // not JSON (Markdown): shown as is
  }
  return `${String(request.method ?? "")} ${String(request.url ?? "")}\n${headers}\n\n${body}`;
}

function Attempts({ workspace, id }: { workspace: string; id: string }) {
  const { t } = useTranslation();
  const push = usePush(workspace, id);
  if (!push) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (!push.attempt_log.length) return <p className="vv-muted">{t("publish.journal.noAttempt")}</p>;
  return (
    <ol className="vv-change-list" aria-label={t("publish.journal.attemptsLabel")}>
      {push.attempt_log.map((a) => (
        <li key={a.attempt_no}>
          <strong>
            {t("publish.journal.attempt", { no: a.attempt_no })} · {formatDate(a.started_at)}
            {a.response_status ? ` · HTTP ${a.response_status}` : ""}
            {a.duration_ms !== null ? ` · ${a.duration_ms} ms` : ""}
            {a.error ? ` · ${a.error}` : ""}
          </strong>
          <details>
            <summary>{t("publish.journal.request")}</summary>
            <pre className="vv-pre">{requestText(a.request)}</pre>
          </details>
          {a.response_excerpt ? (
            <details>
              <summary>{t("publish.journal.response")}</summary>
              <pre className="vv-pre">{a.response_excerpt}</pre>
            </details>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
