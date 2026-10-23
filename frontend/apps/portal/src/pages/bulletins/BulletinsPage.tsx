import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { Alert, Button, DataTable, PageHeader, SelectField, TextField } from "@vv/ui";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";

import { client } from "../../api";
import {
  formatDay,
  type PortalBulletin,
  SEVERITIES,
  type Severity,
  SeverityBadge,
  TlpBadge,
} from "./shared";

const FILTERS = ["q", "severity", "technology", "since", "until"] as const;
type Filter = (typeof FILTERS)[number];

export function BulletinsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const applied = Object.fromEntries(FILTERS.map((k) => [k, params.get(k) ?? ""])) as Record<
    Filter,
    string
  >;
  const page = Math.max(1, Number(params.get("page") ?? "1") || 1);
  const [form, setForm] = useState(applied);

  const bulletins = useQuery({
    queryKey: ["bulletins", applied, page],
    placeholderData: keepPreviousData,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/portal/v1/bulletins", {
          params: {
            query: {
              q: applied.q || null,
              severity: applied.severity ? [applied.severity as Severity] : [],
              technology: applied.technology || null,
              since: applied.since || null,
              until: applied.until || null,
              page,
            },
          },
        }),
      ),
  });

  function go(values: Record<Filter, string>, toPage = 1) {
    const next = new URLSearchParams();
    for (const key of FILTERS) if (values[key]) next.set(key, values[key]);
    if (toPage > 1) next.set("page", String(toPage));
    setParams(next);
  }

  function search(event: FormEvent) {
    event.preventDefault();
    go(form);
  }

  function reset() {
    const empty = Object.fromEntries(FILTERS.map((k) => [k, ""])) as Record<Filter, string>;
    setForm(empty);
    go(empty);
  }

  const set = (key: Filter) => (value: string) => setForm((f) => ({ ...f, [key]: value }));
  const data = bulletins.data;
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <>
      <PageHeader title={t("bulletins.title")} />
      <form className="vv-filters" onSubmit={search} role="search">
        <TextField
          label={t("bulletins.search")}
          hint={t("bulletins.searchHint")}
          value={form.q}
          maxLength={200}
          onChange={(e) => set("q")(e.target.value)}
        />
        <SelectField
          label={t("bulletins.severityLabel")}
          value={form.severity}
          onChange={set("severity")}
          options={[
            { value: "", label: t("bulletins.any") },
            ...SEVERITIES.map((s) => ({ value: s, label: t(`bulletins.severity.${s}`) })),
          ]}
        />
        <TextField
          label={t("bulletins.technology")}
          value={form.technology}
          maxLength={200}
          onChange={(e) => set("technology")(e.target.value)}
        />
        <TextField
          label={t("bulletins.since")}
          type="date"
          value={form.since}
          onChange={(e) => set("since")(e.target.value)}
        />
        <TextField
          label={t("bulletins.until")}
          type="date"
          value={form.until}
          onChange={(e) => set("until")(e.target.value)}
        />
        <Button type="submit">{t("bulletins.apply")}</Button>
        <Button type="button" variant="secondary" onClick={reset}>
          {t("bulletins.reset")}
        </Button>
      </form>
      {bulletins.isError ? <Alert>{errorMessage(t, bulletins.error)}</Alert> : null}
      <DataTable<PortalBulletin>
        rows={data?.items ?? []}
        rowKey={(b) => b.id}
        empty={bulletins.isPending ? t("auth.loading") : t("bulletins.empty")}
        columns={[
          {
            key: "title",
            header: t("bulletins.titleLabel"),
            render: (b) => (
              <>
                <Link to={`/bulletins/${b.id}`}>{b.title}</Link>
                <div className="vv-muted">
                  {b.ref}
                  {b.cves.length ? ` · ${b.cves.join(", ")}` : ""}
                </div>
              </>
            ),
          },
          {
            key: "severity",
            header: t("bulletins.severityLabel"),
            render: (b) => <SeverityBadge severity={b.severity} />,
          },
          { key: "tlp", header: "TLP", render: (b) => <TlpBadge tlp={b.tlp} /> },
          { key: "team", header: t("bulletins.team"), render: (b) => b.team },
          {
            key: "updated",
            header: t("bulletins.updated"),
            render: (b) => formatDay(b.updated_at),
          },
        ]}
      />
      {data && data.total > data.page_size ? (
        <nav className="vv-actions" aria-label={t("bulletins.pagination")}>
          <Button variant="secondary" disabled={page <= 1} onClick={() => go(applied, page - 1)}>
            {t("bulletins.previous")}
          </Button>
          <span className="vv-muted">
            {t("bulletins.pageOf", { page, pages, total: data.total })}
          </span>
          <Button
            variant="secondary"
            disabled={page >= pages}
            onClick={() => go(applied, page + 1)}
          >
            {t("bulletins.next")}
          </Button>
        </nav>
      ) : null}
    </>
  );
}
