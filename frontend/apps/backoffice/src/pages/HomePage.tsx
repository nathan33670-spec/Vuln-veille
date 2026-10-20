import { useMe } from "@vv/auth";
import { Card, PageHeader } from "@vv/ui";
import { useTranslation } from "react-i18next";

export function HomePage() {
  const { t } = useTranslation();
  const me = useMe().data;
  return (
    <>
      <PageHeader title={t("home.title", { name: me?.display_name ?? "" })} />
      <Card title={t("home.workspaces")}>
        {me && me.workspaces.length > 0 ? (
          <ul>
            {me.workspaces.map((w) => (
              <li key={w.slug}>
                {w.name} — {t(`roles.${w.role}`)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="vv-muted">{t("home.noWorkspace")}</p>
        )}
      </Card>
      <Card>
        <p className="vv-muted">{t("home.next")}</p>
      </Card>
    </>
  );
}
