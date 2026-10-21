import { ApiError, type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  DataTable,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";

import { client } from "../../api";
import { formatDate, percent, SeverityBadge } from "../../lib";
import { useWorkspace } from "../../workspace";

type Cve = Schemas["CveOut"];
type Decision = "in_scope" | "out_of_scope" | "pending";
const PAGE = 50;

export function CvesPage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [days, setDays] = useState("7");
  const [decision, setDecision] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string>();
  const scoped = Boolean(slug) && can("watch_scope.manage");

  const cves = useQuery({
    queryKey: ["cves", q, days, decision, kevOnly, offset, scoped ? slug : null],
    placeholderData: keepPreviousData,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/cves", {
          params: {
            query: {
              q: q || null,
              since_days: Number(days),
              kev: kevOnly ? true : null,
              scope_of: scoped ? slug : null,
              decision: (scoped && decision ? decision : null) as Decision | null,
              limit: PAGE,
              offset,
            },
          },
        }),
      ),
  });
  const status = useQuery({
    queryKey: ["sync-status"],
    queryFn: async () => unwrap(await client.GET("/api/v1/cves/sync-status")),
  });

  async function promote(cve: Cve) {
    if (!slug) return;
    try {
      const created = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/vulnerabilities", {
          params: { path: { workspace: slug } },
          body: { cve_id: cve.cve_id, summary: "" },
        }),
      );
      await queryClient.invalidateQueries({ queryKey: ["cves"] });
      navigate(`/vulnerabilities/${created.ref}`);
    } catch (err) {
      if (err instanceof ApiError && err.code.startsWith("exists:")) {
        navigate(`/vulnerabilities/${err.code.slice("exists:".length)}`);
        return;
      }
      setError(errorMessage(t, err));
    }
  }

  return (
    <>
      <PageHeader title={t("cves.title")} />
      <Card title={t("cves.syncTitle")}>
        {(status.data ?? []).length === 0 ? (
          <p className="vv-muted">{t("cves.noSource")}</p>
        ) : (
          <div className="vv-chips">
            {(status.data ?? []).map((s) => (
              <Badge
                key={s.kind}
                tone={!s.enabled ? "neutral" : s.consecutive_failures ? "error" : "ok"}
              >
                {s.name} · {t("cves.lastSuccess")} {formatDate(s.last_success_at)}
                {s.last_error ? ` · ${s.last_error}` : ""}
              </Badge>
            ))}
          </div>
        )}
      </Card>
      <div className="vv-filters">
        <TextField
          label={t("common.search")}
          type="search"
          value={q}
          maxLength={100}
          onChange={(e) => {
            setQ(e.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          label={t("cves.window")}
          value={days}
          onChange={(value) => {
            setDays(value);
            setOffset(0);
          }}
          options={["1", "7", "30", "90"].map((d) => ({
            value: d,
            label: t("cves.days", { count: Number(d) }),
          }))}
        />
        {scoped ? (
          <SelectField
            label={t("cves.decision", { team: slug?.toUpperCase() })}
            value={decision}
            onChange={(value) => {
              setDecision(value);
              setOffset(0);
            }}
            options={[
              { value: "", label: t("common.all") },
              { value: "in_scope", label: t("cves.in_scope") },
              { value: "pending", label: t("cves.pending") },
              { value: "out_of_scope", label: t("cves.out_of_scope") },
            ]}
          />
        ) : null}
        <Checkbox label={t("vulns.kevOnly")} checked={kevOnly} onChange={setKevOnly} />
      </div>
      {error ? <Alert>{error}</Alert> : null}
      {cves.isError ? <Alert>{errorMessage(t, cves.error)}</Alert> : null}
      <DataTable<Cve>
        rows={cves.data?.items ?? []}
        rowKey={(c) => c.cve_id}
        empty={cves.isPending ? t("auth.loading") : t("cves.empty")}
        columns={[
          { key: "id", header: "CVE", render: (c) => c.cve_id },
          {
            key: "published",
            header: t("cves.published"),
            render: (c) => formatDate(c.published_at),
          },
          {
            key: "severity",
            header: t("vulns.severity"),
            render: (c) => <SeverityBadge severity={c.severity} score={c.base_score} />,
          },
          {
            key: "signals",
            header: t("vulns.signals"),
            render: (c) => (
              <span className="vv-chips">
                {c.kev ? <Badge tone="error">KEV</Badge> : null}
                {c.epss_score !== null ? <Badge>EPSS {percent(c.epss_score)}</Badge> : null}
                {c.sources.map((s) => (
                  <Badge key={s}>{s}</Badge>
                ))}
              </span>
            ),
          },
          {
            key: "description",
            header: t("cves.description"),
            render: (c) => <span className="vv-pre">{c.description.slice(0, 220)}</span>,
          },
          ...(scoped
            ? [
                {
                  key: "scope",
                  header: t("cves.scope"),
                  render: (c: Cve) =>
                    c.scope_decision ? (
                      <span title={(c.scope_reasons ?? []).join(", ")}>
                        <Badge
                          tone={
                            c.scope_decision === "in_scope"
                              ? "ok"
                              : c.scope_decision === "pending"
                                ? "warn"
                                : "neutral"
                          }
                        >
                          {t(`cves.${c.scope_decision}`)}
                        </Badge>
                      </span>
                    ) : (
                      "—"
                    ),
                },
              ]
            : []),
          {
            key: "action",
            header: "",
            render: (c) =>
              c.vulnerability_ref ? (
                <Link to={`/vulnerabilities/${c.vulnerability_ref}`}>{c.vulnerability_ref}</Link>
              ) : slug && can("vuln.qualify") ? (
                <Button variant="secondary" onClick={() => promote(c)}>
                  {t("cves.promote")}
                </Button>
              ) : null,
          },
        ]}
      />
      <div className="vv-actions">
        <Button
          variant="secondary"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE))}
        >
          {t("common.previous")}
        </Button>
        <Button
          variant="secondary"
          disabled={!cves.data || offset + PAGE >= cves.data.total}
          onClick={() => setOffset(offset + PAGE)}
        >
          {t("common.next")}
        </Button>
      </div>
    </>
  );
}
