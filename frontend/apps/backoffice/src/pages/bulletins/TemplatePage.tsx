import { ApiError, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  DataTable,
  PageHeader,
  SafeHtml,
  SelectField,
  TextArea,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { apiDetail, parseObject } from "../ai/shared";
import { TemplateStatusBadge } from "./TemplatesPage";

type Message = { tone: "error" | "success"; text: string };
const PREVIEW_DELAY_MS = 700;

/** Template editor (6.3): JSON spec, validated and previewed by the server. */
export function TemplatePage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug, can } = useWorkspace();
  const workspace = slug ?? "";
  const queryClient = useQueryClient();
  const key = ["bulletin-template", workspace, id];
  const [message, setMessage] = useState<Message>();
  const template = useQuery({
    queryKey: key,
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletin-templates/{template_id}", {
          params: { path: { workspace, template_id: id } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
      await queryClient.invalidateQueries({ queryKey: ["bulletin-templates", workspace] });
      return true;
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
      return false;
    }
  }

  if (template.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (template.isError) return <Alert>{errorMessage(t, template.error)}</Alert>;
  const tpl = template.data;
  const manager = can("template.manage");
  const path = { workspace, template_id: id };
  const activate = (versionNo: number) =>
    act(
      async () =>
        unwrap(
          await client.POST(
            "/api/v1/workspaces/{workspace}/bulletin-templates/{template_id}/versions/{version_no}/activate",
            { params: { path: { ...path, version_no: versionNo } } },
          ),
        ),
      t("bulletins.templates.activated", { no: versionNo }),
    );
  const archive = () =>
    act(
      async () =>
        unwrap(
          await client.PATCH("/api/v1/workspaces/{workspace}/bulletin-templates/{template_id}", {
            params: { path },
            body: {
              status: tpl.status === "archived" ? "active" : "archived",
              version: tpl.version,
            },
          }),
        ),
      tpl.status === "archived"
        ? t("bulletins.templates.restored")
        : t("bulletins.templates.archived"),
    );

  return (
    <>
      <PageHeader
        title={tpl.name}
        actions={<Link to="/bulletin-templates">{t("bulletins.templates.back")}</Link>}
      />
      <p className="vv-actions">
        <TemplateStatusBadge status={tpl.status} />
        {tpl.is_default ? <Badge tone="ok">{t("bulletins.templates.default")}</Badge> : null}
        <span className="vv-muted">
          {tpl.active_version_no
            ? t("bulletins.templates.activeIs", { no: tpl.active_version_no })
            : t("bulletins.templates.noActive")}
        </span>
        {manager && tpl.active_version_no ? (
          <Button variant="secondary" onClick={() => void archive()}>
            {tpl.status === "archived"
              ? t("bulletins.templates.restore")
              : t("bulletins.templates.archive")}
          </Button>
        ) : null}
      </p>
      {tpl.description ? <p>{tpl.description}</p> : null}
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <SpecEditor
        key={tpl.latest_version_no ?? 0}
        workspace={workspace}
        initial={tpl.latest_spec ?? {}}
        readOnly={!manager}
        onSave={async (spec, comment) =>
          act(
            async () =>
              unwrap(
                await client.POST(
                  "/api/v1/workspaces/{workspace}/bulletin-templates/{template_id}/versions",
                  {
                    params: { path },
                    body: {
                      spec: spec as Record<string, never>,
                      comment,
                      base_version_no: tpl.latest_version_no ?? null,
                    },
                  },
                ),
              ),
            t("bulletins.templates.versionSaved"),
          )
        }
      />
      <Card title={t("bulletins.templates.versions")}>
        <DataTable
          rows={tpl.versions}
          rowKey={(v) => String(v.version_no)}
          empty="—"
          columns={[
            { key: "no", header: "#", render: (v) => `v${v.version_no}` },
            {
              key: "language",
              header: t("bulletins.languageColumn"),
              render: (v) => v.language.toUpperCase(),
            },
            {
              key: "priority",
              header: t("bulletins.templates.priority"),
              render: (v) => v.priority,
            },
            {
              key: "comment",
              header: t("bulletins.templates.comment"),
              render: (v) => v.comment || "—",
            },
            {
              key: "created",
              header: t("bulletins.templates.created"),
              render: (v) => formatDate(v.created_at),
            },
            {
              key: "actions",
              header: "",
              render: (v) =>
                v.version_no === tpl.active_version_no ? (
                  <Badge tone="ok">{t("bulletins.templates.active")}</Badge>
                ) : manager ? (
                  <Button variant="secondary" onClick={() => void activate(v.version_no)}>
                    {t("bulletins.templates.activate")}
                  </Button>
                ) : null,
            },
          ]}
        />
      </Card>
    </>
  );
}

function SpecEditor({
  workspace,
  initial,
  readOnly,
  onSave,
}: {
  workspace: string;
  initial: Record<string, unknown>;
  readOnly: boolean;
  onSave: (spec: Record<string, unknown>, comment: string) => Promise<boolean>;
}) {
  const { t } = useTranslation();
  const original = useMemo(() => JSON.stringify(initial, null, 2), [initial]);
  const [text, setText] = useState(original);
  const [comment, setComment] = useState("");
  const [search, setSearch] = useState("");
  const [vulnerabilityId, setVulnerabilityId] = useState("");
  const [preview, setPreview] = useState<{
    html: string;
    matches: boolean | null;
    reasons: string[];
  }>();
  const [errors, setErrors] = useState<string[]>([]);
  const spec = useMemo(() => parseObject(text), [text]);
  const vulnerabilities = useQuery({
    queryKey: ["vulnerability-search", search],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/vulnerabilities", {
          params: { query: { q: search || null, limit: 20 } },
        }),
      ),
  });

  // Rendered by the server with production rules: computed fields from the chosen
  // vulnerability, AI and manual fields as placeholders (no AI call).
  useEffect(() => {
    if (!spec) return;
    const timer = window.setTimeout(async () => {
      try {
        const out = unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/bulletin-templates/preview", {
            params: { path: { workspace } },
            body: {
              spec: spec as Record<string, never>,
              vulnerability_id: vulnerabilityId || null,
            },
          }),
        );
        setPreview({ html: out.html, matches: out.matches ?? null, reasons: out.reasons });
        setErrors([]);
      } catch (err) {
        setErrors(
          err instanceof ApiError && err.errors.length
            ? err.errors.map(
                (e) => `${e.path} : ${t(`bulletins.templates.error.${e.code}`, e.code)}`,
              )
            : [apiDetail(t, err)],
        );
      }
    }, PREVIEW_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [spec, vulnerabilityId, workspace, t]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!spec) return;
    if (await onSave(spec, comment)) setComment("");
  }

  return (
    <div className="vv-grid-2">
      <Card title={t("bulletins.templates.spec")}>
        <form className="vv-form" onSubmit={save}>
          <TextArea
            label={t("bulletins.templates.specLabel")}
            hint={t("bulletins.templates.specHint")}
            className="vv-textarea vv-mono"
            rows={28}
            value={text}
            readOnly={readOnly}
            spellCheck={false}
            onChange={(e) => setText(e.target.value)}
          />
          {!spec ? <Alert>{t("ai.invalidJson")}</Alert> : null}
          {errors.length ? (
            <Alert>
              <ul>
                {errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </Alert>
          ) : null}
          {!readOnly ? (
            <>
              <TextField
                label={t("bulletins.templates.comment")}
                value={comment}
                maxLength={500}
                onChange={(e) => setComment(e.target.value)}
              />
              <Button type="submit" disabled={!spec || text === original || errors.length > 0}>
                {t("bulletins.templates.saveVersion")}
              </Button>
            </>
          ) : null}
        </form>
      </Card>
      <Card title={t("bulletins.templates.preview")}>
        <div className="vv-filters">
          <TextField
            label={t("bulletins.templates.searchVulnerability")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <SelectField
            label={t("bulletins.templates.previewOn")}
            value={vulnerabilityId}
            onChange={setVulnerabilityId}
            options={[
              { value: "", label: t("bulletins.templates.noVulnerability") },
              ...(vulnerabilities.data?.items ?? []).map((v) => ({
                value: v.id,
                label: `${v.cve_id ?? v.ref} — ${v.title}`.slice(0, 120),
              })),
            ]}
          />
        </div>
        {preview && vulnerabilityId && preview.matches !== null ? (
          <Alert tone="info">
            {preview.matches
              ? t("bulletins.templates.matches", { reasons: preview.reasons.join(" ; ") })
              : t("bulletins.templates.noMatch")}
          </Alert>
        ) : null}
        {preview ? <SafeHtml className="vv-bulletin" html={preview.html} /> : null}
      </Card>
    </div>
  );
}
