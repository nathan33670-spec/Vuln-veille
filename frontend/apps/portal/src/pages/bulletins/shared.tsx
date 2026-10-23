import type { PortalSchemas } from "@vv/api-client";
import { Badge } from "@vv/ui";
import { useTranslation } from "react-i18next";

export type PortalBulletin = PortalSchemas["PortalBulletinOut"];
export type PortalBulletinDetail = PortalSchemas["PortalBulletinDetailOut"];

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function formatDay(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleDateString("fr-FR") : "—";
}

const TLP_TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  CLEAR: "neutral",
  GREEN: "ok",
  AMBER: "warn",
  "AMBER+STRICT": "warn",
  RED: "error",
};

export function TlpBadge({ tlp }: { tlp: string }) {
  return <Badge tone={TLP_TONE[tlp] ?? "neutral"}>TLP:{tlp}</Badge>;
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const { t } = useTranslation();
  if (!severity) return <Badge>—</Badge>;
  const tone = severity === "low" ? "ok" : severity === "medium" ? "warn" : "error";
  return <Badge tone={tone}>{t(`bulletins.severity.${severity}`, severity)}</Badge>;
}

/** Same-origin download: the session cookie goes with it, the server sets the file name. */
export function exportUrl(id: string, format: "markdown" | "html" | "pdf"): string {
  return `/api/portal/v1/bulletins/${encodeURIComponent(id)}/export?format=${format}`;
}
