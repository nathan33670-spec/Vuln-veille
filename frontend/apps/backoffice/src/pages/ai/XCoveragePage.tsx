import { type Schemas, unwrap } from "@vv/api-client";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  DataTable,
  ExternalLink,
  PageHeader,
  SelectField,
  TextArea,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate, splitList } from "../../lib";
import { useWorkspace } from "../../workspace";
import { apiDetail, rate } from "./shared";

type Check = Schemas["XCoverageCheckOut"];

export function XCoveragePage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const queryClient = useQueryClient();
  const workspace = slug ?? "";
  const [days, setDays] = useState("30");
  const [hasDiscussion, setHasDiscussion] = useState(true);
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const coverage = useQuery({
    queryKey: ["x-coverage", workspace, days],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/x-coverage", {
          params: { path: { workspace }, query: { days: Number(days) } },
        }),
      ),
  });
  const checks = useQuery({
    queryKey: ["x-coverage-checks", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/x-coverage/checks", {
          params: { path: { workspace } },
        }),
      ),
  });

  async function record(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const cve = String(form.get("cve_id")).trim().toUpperCase();
    try {
      unwrap(
        await client.PUT("/api/v1/workspaces/{workspace}/x-coverage/checks/{cve_id}", {
          params: { path: { workspace, cve_id: cve } },
          body: {
            has_discussion: hasDiscussion,
            urls: splitList(String(form.get("urls") ?? "").replaceAll("\n", ",")),
            notes: String(form.get("notes") ?? ""),
          },
        }),
      );
      setMessage({ tone: "success", text: t("ai.x.recorded") });
      formElement.reset();
      await queryClient.invalidateQueries({ queryKey: ["x-coverage-checks", workspace] });
      await queryClient.invalidateQueries({ queryKey: ["x-coverage", workspace] });
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  const c = coverage.data;
  const sample = (c?.sample ?? {}) as Record<string, unknown>;
  const missed = Array.isArray(sample.missed) ? (sample.missed as string[]) : [];
  return (
    <>
      <PageHeader title={t("ai.x.title", { team: workspace.toUpperCase() })} />
      <p className="vv-muted">{t("ai.x.intro")}</p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <SelectField
        label={t("ai.x.window")}
        value={days}
        onChange={setDays}
        options={["7", "30", "90"].map((d) => ({
          value: d,
          label: t("ai.x.days", { count: Number(d) }),
        }))}
      />
      <div className="vv-grid-2">
        <Card title={t("ai.x.indicator")}>
          <dl className="vv-kv">
            <dt>{t("ai.x.investigated")}</dt>
            <dd>{c?.investigated ?? "—"}</dd>
            <dt>{t("ai.x.withX")}</dt>
            <dd>{c?.with_x_discussion ?? "—"}</dd>
            <dt>{t("ai.x.rate")}</dt>
            <dd>{rate(c?.coverage_rate)}</dd>
          </dl>
        </Card>
        <Card title={t("ai.x.sample")}>
          <dl className="vv-kv">
            <dt>{t("ai.x.compared")}</dt>
            <dd>{String(sample.compared ?? "—")}</dd>
            <dt>{t("ai.x.recall")}</dt>
            <dd>{rate(sample.recall as number | null)}</dd>
            <dt>{t("ai.x.precision")}</dt>
            <dd>{rate(sample.precision as number | null)}</dd>
            <dt>{t("ai.x.missed")}</dt>
            <dd>{missed.length ? missed.join(", ") : "—"}</dd>
          </dl>
        </Card>
      </div>
      <Card title={t("ai.x.checks")}>
        <DataTable<Check>
          rows={checks.data ?? []}
          rowKey={(k) => k.cve_id}
          empty={t("ai.x.noChecks")}
          columns={[
            { key: "cve", header: "CVE", render: (k) => k.cve_id },
            {
              key: "has",
              header: t("ai.x.hasDiscussion"),
              render: (k) =>
                k.has_discussion ? (
                  <Badge tone="ok">{t("ai.x.yes")}</Badge>
                ) : (
                  <Badge>{t("ai.x.no")}</Badge>
                ),
            },
            {
              key: "urls",
              header: t("ai.x.urls"),
              render: (k) =>
                k.urls.length
                  ? k.urls.map((u) => (
                      <div key={u}>
                        <ExternalLink href={u}>{u}</ExternalLink>
                      </div>
                    ))
                  : "—",
            },
            { key: "date", header: t("ai.agents.date"), render: (k) => formatDate(k.checked_at) },
          ]}
        />
        {can("vuln.qualify") ? (
          <form className="vv-form" onSubmit={record}>
            <TextField label="CVE" name="cve_id" required pattern="CVE-\d{4}-\d{4,19}" />
            <Checkbox
              label={t("ai.x.hasDiscussion")}
              checked={hasDiscussion}
              onChange={setHasDiscussion}
            />
            <TextArea label={t("ai.x.urls")} name="urls" rows={3} hint={t("ai.x.urlsHint")} />
            <TextField label={t("ai.eval.notes")} name="notes" maxLength={1000} />
            <div className="vv-actions">
              <Button type="submit">{t("ai.x.record")}</Button>
            </div>
          </form>
        ) : null}
      </Card>
    </>
  );
}
