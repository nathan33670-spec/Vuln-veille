import { Card, PageHeader } from "@vv/ui";
import { useTranslation } from "react-i18next";

export function HomePage() {
  const { t } = useTranslation();
  return (
    <>
      <PageHeader title={t("bulletins.title")} />
      <Card>
        <p className="vv-muted">{t("bulletins.empty")}</p>
      </Card>
    </>
  );
}
