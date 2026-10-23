import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, Card, PageHeader, SafeHtml } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";

import { client } from "../../api";
import { exportUrl, formatDay, SeverityBadge, TlpBadge } from "./shared";

export function BulletinPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const bulletin = useQuery({
    queryKey: ["bulletins", id],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/portal/v1/bulletins/{bulletin_id}", {
          params: { path: { bulletin_id: id } },
        }),
      ),
  });
  if (bulletin.isError) {
    return (
      <>
        <Alert>{errorMessage(t, bulletin.error)}</Alert>
        <Link to="/">{t("bulletins.back")}</Link>
      </>
    );
  }
  const b = bulletin.data;
  if (!b) return <p className="vv-muted">{t("auth.loading")}</p>;
  return (
    <>
      <p className="vv-no-print">
        <Link to="/">{t("bulletins.back")}</Link>
      </p>
      <PageHeader
        title={`${b.ref} — ${b.title}`}
        actions={
          <div className="vv-actions vv-no-print">
            <a className="vv-button vv-button-secondary" href={exportUrl(b.id, "pdf")} download>
              {t("bulletins.exportPdf")}
            </a>
            <a className="vv-button vv-button-secondary" href={exportUrl(b.id, "html")} download>
              {t("bulletins.exportHtml")}
            </a>
            <a
              className="vv-button vv-button-secondary"
              href={exportUrl(b.id, "markdown")}
              download
            >
              {t("bulletins.exportMarkdown")}
            </a>
            <Button variant="secondary" onClick={() => window.print()}>
              {t("bulletins.print")}
            </Button>
          </div>
        }
      />
      <div className="vv-meta">
        <TlpBadge tlp={b.tlp} />
        <SeverityBadge severity={b.severity} />
        <span className="vv-muted">
          {t("bulletins.issuedBy", { team: b.team })} ·{" "}
          {t("bulletins.publishedOn", { date: formatDay(b.published_at) })}
          {b.updated_at > b.published_at
            ? ` · ${t("bulletins.updatedOn", { date: formatDay(b.updated_at) })}`
            : ""}
        </span>
      </div>
      {b.cves.length || b.technologies.length ? (
        <dl className="vv-meta">
          {b.cves.length ? (
            <>
              <dt>{t("bulletins.cves")}</dt>
              <dd>{b.cves.join(", ")}</dd>
            </>
          ) : null}
          {b.technologies.length ? (
            <>
              <dt>{t("bulletins.technologies")}</dt>
              <dd>{b.technologies.map((tech) => tech.name || tech.product).join(", ")}</dd>
            </>
          ) : null}
        </dl>
      ) : null}
      <Card>
        <SafeHtml className="vv-bulletin" html={b.html} />
      </Card>
      {b.history.length ? (
        <Card title={t("bulletins.history")}>
          <ul>
            {b.history.map((h) => (
              <li key={`${h.kind}-${h.at}`}>
                {t(`bulletins.kinds.${h.kind}`, h.kind)} — {new Date(h.at).toLocaleString("fr-FR")}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </>
  );
}
