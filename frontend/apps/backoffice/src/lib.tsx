import { Badge } from "@vv/ui";

export function formatDate(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString("fr-FR") : "—";
}

export function formatDay(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleDateString("fr-FR") : "—";
}

const SEVERITY_TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warn",
  LOW: "ok",
  NONE: "neutral",
};

export function SeverityBadge({
  severity,
  score,
}: {
  severity: string | null | undefined;
  score?: string | number | null;
}) {
  if (!severity) return <Badge>—</Badge>;
  return (
    <Badge tone={SEVERITY_TONE[severity] ?? "neutral"}>
      {severity}
      {score !== null && score !== undefined ? ` ${score}` : ""}
    </Badge>
  );
}

/** "a, b , c" -> ["a", "b", "c"] (empty entries dropped). */
export function splitList(value: string): string[] {
  return value
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

export function percent(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${(Number(value) * 100).toFixed(1)} %`;
}
