import { AppShell } from "@vv/ui";
import { useTranslation } from "react-i18next";

import { useApiHealth } from "./useApiHealth";

export function App() {
  const { t } = useTranslation();
  const health = useApiHealth();
  return (
    <AppShell title={t("app.title")} subtitle={t("app.subtitle")}>
      <p>{t("app.placeholder")}</p>
      <p className={health === "error" ? "vv-status-error" : "vv-status-ok"} role="status">
        {t(`health.${health}`)}
      </p>
    </AppShell>
  );
}
