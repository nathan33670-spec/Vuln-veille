import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  DataTable,
  PageHeader,
  SelectField,
  Tabs,
  TextField,
} from "@vv/ui";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { client } from "../../api";
import { percent, SeverityBadge } from "../../lib";
import { useWorkspace } from "../../workspace";

type Vulnerability = Schemas["VulnerabilitySummaryOut"];
type State = "unqualified" | "qualified" | "monitoring" | "all";
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
const PAGE = 50;

export function VulnerabilitiesPage() {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const [state, setState] = useState<State>("unqualified");
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [mine, setMine] = useState(false);
  const [offset, setOffset] = useState(0);

  const list = useQuery({
    queryKey: ["vulns", slug, state, q, severity, kevOnly, mine, offset],
    placeholderData: keepPreviousData,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/vulnerabilities", {
          params: {
            query: {
              team: slug,
              state,
              q: q || null,
              severity: (severity || null) as Severity | null,
              kev: kevOnly ? true : null,
              assigned_to_me: mine,
              limit: PAGE,
              offset,
            },
          },
        }),
      ),
  });

  const mineOf = (v: Vulnerability) => v.assessments.find((a) => a.workspace === slug);
  const others = (v: Vulnerability) => v.assessments.filter((a) => a.workspace !== slug);

  return (
    <>
      <PageHeader title={t("vulns.title")} />
      <Tabs<State>
        label={t("vulns.state")}
        value={state}
        onChange={(value) => {
          setState(value);
          setOffset(0);
        }}
        options={[
          { value: "unqualified", label: t("vulns.toQualify") },
          { value: "qualified", label: t("vulns.qualified") },
          { value: "monitoring", label: t("vulns.monitoring") },
          { value: "all", label: t("vulns.all") },
        ]}
      />
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
          label={t("vulns.severity")}
          value={severity}
          onChange={(value) => {
            setSeverity(value);
            setOffset(0);
          }}
          options={[
            { value: "", label: t("common.all") },
            ...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => ({ value: s, label: s })),
          ]}
        />
        <Checkbox label={t("vulns.kevOnly")} checked={kevOnly} onChange={setKevOnly} />
        <Checkbox label={t("vulns.assignedToMe")} checked={mine} onChange={setMine} />
      </div>
      {list.isError ? <Alert>{errorMessage(t, list.error)}</Alert> : null}
      <DataTable<Vulnerability>
        rows={list.data?.items ?? []}
        rowKey={(v) => v.id}
        empty={list.isPending ? t("auth.loading") : t("vulns.empty")}
        columns={[
          {
            key: "ref",
            header: t("vulns.ref"),
            render: (v) => <Link to={`/vulnerabilities/${v.ref}`}>{v.ref}</Link>,
          },
          { key: "cve", header: "CVE", render: (v) => v.cve_id ?? "—" },
          { key: "title", header: t("vulns.titleColumn"), render: (v) => v.title },
          {
            key: "severity",
            header: t("vulns.severity"),
            render: (v) => <SeverityBadge severity={v.severity} score={v.base_score} />,
          },
          {
            key: "signals",
            header: t("vulns.signals"),
            render: (v) => (
              <span className="vv-chips">
                {v.kev ? <Badge tone="error">KEV</Badge> : null}
                {v.epss_score !== null ? <Badge>EPSS {percent(v.epss_score)}</Badge> : null}
              </span>
            ),
          },
          {
            key: "mine",
            header: t("vulns.myTeam"),
            render: (v) => {
              const a = mineOf(v);
              return a
                ? `${t(`vulns.status.${a.status}`)}${a.priority ? ` · ${a.priority}` : ""}`
                : t("vulns.status.new");
            },
          },
          {
            key: "others",
            header: t("vulns.otherTeam"),
            render: (v) =>
              others(v).map((a) => (
                <Badge key={a.id} tone={a.status === "qualified" ? "ok" : "neutral"}>
                  {a.workspace.toUpperCase()} {t(`vulns.status.${a.status}`)}
                  {a.priority ? ` ${a.priority}` : ""}
                </Badge>
              )),
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
        <span className="vv-muted">
          {list.data
            ? t("common.range", {
                from: offset + 1,
                to: offset + list.data.items.length,
                total: list.data.total,
              })
            : ""}
        </span>
        <Button
          variant="secondary"
          disabled={!list.data || offset + PAGE >= list.data.total}
          onClick={() => setOffset(offset + PAGE)}
        >
          {t("common.next")}
        </Button>
      </div>
    </>
  );
}
