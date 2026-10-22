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

/** Saves a value as a JSON file (export of a workflow…). */
export function downloadJson(filename: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A file name from free text ("Nouvelle CVE NVD → investigation" → "nouvelle-cve-nvd-investigation"). */
export function slugify(text: string): string {
  return (
    text
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 60) || "workflow"
  );
}
