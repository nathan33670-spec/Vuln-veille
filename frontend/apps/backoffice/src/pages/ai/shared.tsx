import { ApiError } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Badge } from "@vv/ui";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";

const TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  queued: "neutral",
  running: "warn",
  succeeded: "ok",
  skipped: "neutral",
  failed: "error",
  refused: "warn",
  invalid_output: "error",
  budget_exceeded: "warn",
  timed_out: "error",
};

export const TERMINAL = new Set([
  "succeeded",
  "failed",
  "refused",
  "invalid_output",
  "budget_exceeded",
  "timed_out",
]);

export function AgentStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return <Badge tone={TONE[status] ?? "neutral"}>{t(`ai.status.${status}`, status)}</Badge>;
}

export function money(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Number(value).toFixed(4)} $`;
}

export function rate(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${(value * 100).toFixed(0)} %`;
}

/** A server error: its translation, else its stable code (codes never carry data). */
export function apiDetail(t: TFunction, error: unknown): string {
  if (error instanceof ApiError) {
    const [code, ...rest] = error.code.split(":");
    const key = `errors.${code}`;
    const translated = t(key);
    if (translated !== key) return rest.length ? `${translated} (${rest.join(":")})` : translated;
    return error.code;
  }
  return errorMessage(t, error);
}

interface Flag {
  kind?: string;
  source?: string;
  detail?: string;
}

/** Injection signals, shown as text: they quote collected content. */
export function FlagList({ flags }: { flags: unknown[] }) {
  const { t } = useTranslation();
  if (flags.length === 0) return <p className="vv-muted">{t("ai.noFlags")}</p>;
  return (
    <ul className="vv-timeline">
      {(flags as Flag[]).map((f, index) => {
        const kind = f.kind ?? "";
        const base = kind.startsWith("suspicious_poc:") ? "suspicious_poc" : kind;
        return (
          <li key={`${kind}-${index}`}>
            <Badge tone="warn">{t(`ai.flags.${base}`, kind)}</Badge>{" "}
            <span className="vv-muted">{f.source}</span>{" "}
            {f.detail ? <code className="vv-untrusted">{f.detail}</code> : null}
          </li>
        );
      })}
    </ul>
  );
}

/** Parses a JSON object typed by an analyst; null when it is not one. */
export function parseObject(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
