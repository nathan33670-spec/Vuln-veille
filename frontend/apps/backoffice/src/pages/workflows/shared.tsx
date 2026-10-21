import type { FieldError } from "@vv/api-client";
import { Badge } from "@vv/ui";
import { useTranslation } from "react-i18next";

const RUN_TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  queued: "neutral",
  running: "warn",
  waiting_approval: "warn",
  succeeded: "ok",
  skipped: "neutral",
  failed: "error",
  cancelled: "neutral",
  timed_out: "error",
  draft: "neutral",
  active: "ok",
  paused: "warn",
  archived: "neutral",
};

export const TERMINAL = new Set(["succeeded", "failed", "cancelled", "timed_out"]);

export function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return <Badge tone={RUN_TONE[status] ?? "neutral"}>{t(`workflows.status.${status}`)}</Badge>;
}

export function duration(start: string | null | undefined, end: string | null | undefined) {
  if (!start || !end) return "—";
  const seconds = (new Date(end).getTime() - new Date(start).getTime()) / 1000;
  return seconds < 60 ? `${seconds.toFixed(1)} s` : `${Math.round(seconds / 60)} min`;
}

/** Validation errors of a graph, located by path (nodes.2.params.url…). */
export function GraphErrors({ errors }: { errors: FieldError[] }) {
  const { t } = useTranslation();
  if (errors.length === 0) return null;
  return (
    <ul className="vv-timeline">
      {errors.map((e) => (
        <li key={`${e.path}:${e.code}`}>
          <code>{e.path || "—"}</code> : {t(`workflows.graphErrors.${e.code}`, e.code)}
        </li>
      ))}
    </ul>
  );
}

/** JSON shown as text: collected content stays inert data. */
export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="vv-pre vv-untrusted">{JSON.stringify(value, null, 2)}</pre>;
}
