import type { Schemas } from "@vv/api-client";
import { Badge } from "@vv/ui";
import { useTranslation } from "react-i18next";

export type User = Schemas["UserOut"];

export function formatDate(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString("fr-FR") : "—";
}

export function StatusBadge({ user }: { user: User }) {
  const { t } = useTranslation();
  if (user.locked) return <Badge tone="error">{t("admin.locked")}</Badge>;
  const tone = user.status === "active" ? "ok" : user.status === "invited" ? "warn" : "error";
  return <Badge tone={tone}>{t(`admin.status.${user.status}`)}</Badge>;
}
