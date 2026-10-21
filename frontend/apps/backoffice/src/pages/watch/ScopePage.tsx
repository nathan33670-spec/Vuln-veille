import { type Schemas, unwrap } from "@vv/api-client";
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
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate, SeverityBadge, splitList } from "../../lib";
import { useWorkspace } from "../../workspace";

type Scope = Schemas["WatchScopeOut"];
type Technology = Schemas["TechnologyOut"];

export function ScopePage() {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const queryClient = useQueryClient();
  const path = { params: { path: { workspace: slug ?? "" } } };
  const scope = useQuery({
    queryKey: ["scope", slug],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(await client.GET("/api/v1/workspaces/{workspace}/watch-scope", path)),
  });
  const preview = useQuery({
    queryKey: ["scope-preview", slug, scope.data?.version],
    enabled: Boolean(slug && scope.data),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/watch-scope/preview", {
          ...path,
          params: { ...path.params, query: { days: 7, limit: 50 } },
        }),
      ),
  });
  if (!slug) return <Alert tone="info">{t("workspace.none")}</Alert>;
  if (scope.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (scope.isError) return <Alert>{errorMessage(t, scope.error)}</Alert>;

  return (
    <>
      <PageHeader title={t("scope.title", { team: slug.toUpperCase() })} />
      <div className="vv-grid-2">
        <ScopeForm
          scope={scope.data}
          slug={slug}
          onSaved={() => queryClient.invalidateQueries({ queryKey: ["scope", slug] })}
        />
        <Card title={t("scope.preview")}>
          {preview.data ? (
            <>
              <p>
                {t("scope.previewSummary", {
                  total: preview.data.total,
                  in: preview.data.in_scope,
                  pending: preview.data.pending,
                  out: preview.data.out_of_scope,
                })}
              </p>
              <DataTable<Schemas["ScopePreviewItem"]>
                rows={preview.data.items}
                rowKey={(i) => i.cve_id}
                empty={t("scope.nothing")}
                columns={[
                  { key: "id", header: "CVE", render: (i) => i.cve_id },
                  {
                    key: "date",
                    header: t("cves.published"),
                    render: (i) => formatDate(i.published_at),
                  },
                  {
                    key: "severity",
                    header: t("vulns.severity"),
                    render: (i) => <SeverityBadge severity={i.severity} score={i.base_score} />,
                  },
                  {
                    key: "decision",
                    header: t("cves.scope"),
                    render: (i) => (
                      <Badge tone={i.decision === "in_scope" ? "ok" : "warn"}>
                        {t(`cves.${i.decision}`)}
                      </Badge>
                    ),
                  },
                  {
                    key: "reasons",
                    header: t("scope.reasons"),
                    render: (i) => i.reasons.join(", "),
                  },
                ]}
              />
            </>
          ) : (
            <p className="vv-muted">{t("auth.loading")}</p>
          )}
        </Card>
      </div>
    </>
  );
}

function ScopeForm({
  scope,
  slug,
  onSaved,
}: {
  scope: Scope;
  slug: string;
  onSaved: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [mode, setMode] = useState(scope.mode);
  const [techIds, setTechIds] = useState<string[]>(scope.technology_ids);
  const [vendors, setVendors] = useState(scope.vendors.join(", "));
  const [keywords, setKeywords] = useState(scope.keywords.join(", "));
  const [cvssMin, setCvssMin] = useState(scope.cvss_min ?? "");
  const [unscored, setUnscored] = useState(scope.include_unscored);
  const [kev, setKev] = useState(scope.always_include_kev);
  const [cweInclude, setCweInclude] = useState(scope.cwe_include.join(", "));
  const [cweExclude, setCweExclude] = useState(scope.cwe_exclude.join(", "));
  const [search, setSearch] = useState("");
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();

  const followed = useQuery({
    queryKey: ["technologies", "all"],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/technologies", {
          params: { query: { limit: 200, include_merged: true } },
        }),
      ),
  });
  const found = useQuery({
    queryKey: ["technologies", search],
    enabled: search.length >= 2,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/technologies", { params: { query: { q: search, limit: 10 } } }),
      ),
  });
  const byId = new Map<string, Technology>((followed.data ?? []).map((tech) => [tech.id, tech]));

  async function save(event: FormEvent) {
    event.preventDefault();
    try {
      unwrap(
        await client.PUT("/api/v1/workspaces/{workspace}/watch-scope", {
          params: { path: { workspace: slug } },
          body: {
            version: scope.version,
            mode: mode as "all" | "scoped",
            technology_ids: techIds,
            vendors: splitList(vendors),
            keywords: splitList(keywords),
            cvss_min: cvssMin === "" ? null : String(cvssMin),
            include_unscored: unscored as "include" | "wait" | "exclude",
            always_include_kev: kev,
            cwe_include: splitList(cweInclude),
            cwe_exclude: splitList(cweExclude),
          },
        }),
      );
      setMessage({ tone: "success", text: t("scope.saved") });
      await onSaved();
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  return (
    <Card title={t("scope.settings")}>
      <form className="vv-form" onSubmit={save}>
        {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
        <SelectField
          label={t("scope.mode")}
          value={mode}
          onChange={setMode}
          options={[
            { value: "scoped", label: t("scope.scoped") },
            { value: "all", label: t("scope.all") },
          ]}
        />
        <div>
          <strong>{t("scope.technologies")}</strong>
          <div className="vv-chips">
            {techIds.map((id) => (
              <Button
                key={id}
                variant="secondary"
                onClick={() => setTechIds(techIds.filter((x) => x !== id))}
              >
                {byId.get(id)?.display_name ?? id} ×
              </Button>
            ))}
          </div>
          <TextField
            label={t("scope.addTechnology")}
            type="search"
            value={search}
            maxLength={100}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div className="vv-chips">
            {(found.data ?? [])
              .filter((tech) => !techIds.includes(tech.id))
              .map((tech) => (
                <Button
                  key={tech.id}
                  variant="secondary"
                  onClick={() => setTechIds([...techIds, tech.id])}
                >
                  + {tech.display_name}
                </Button>
              ))}
          </div>
        </div>
        <TextField
          label={t("scope.vendors")}
          hint={t("scope.listHint")}
          value={vendors}
          onChange={(e) => setVendors(e.target.value)}
        />
        <TextField
          label={t("scope.keywords")}
          hint={t("scope.listHint")}
          value={keywords}
          onChange={(e) => setKeywords(e.target.value)}
        />
        <TextField
          label={t("scope.cvssMin")}
          type="number"
          min={0}
          max={10}
          step={0.1}
          value={cvssMin}
          onChange={(e) => setCvssMin(e.target.value)}
        />
        <SelectField
          label={t("scope.unscored")}
          value={unscored}
          onChange={setUnscored}
          options={["wait", "include", "exclude"].map((v) => ({
            value: v,
            label: t(`scope.unscored_${v}`),
          }))}
        />
        <Checkbox label={t("scope.kev")} checked={kev} onChange={setKev} />
        <TextField
          label={t("scope.cweInclude")}
          hint="CWE-79, CWE-89"
          value={cweInclude}
          onChange={(e) => setCweInclude(e.target.value)}
        />
        <TextField
          label={t("scope.cweExclude")}
          hint="CWE-79, CWE-89"
          value={cweExclude}
          onChange={(e) => setCweExclude(e.target.value)}
        />
        <div className="vv-actions">
          <Button type="submit">{t("common.save")}</Button>
        </div>
      </form>
    </Card>
  );
}
