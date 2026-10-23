import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  DataTable,
  Dialog,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { apiDetail } from "../ai/shared";

type Template = Schemas["TemplateOut"];
type Message = { tone: "error" | "success"; text: string };

const TEMPLATE_TONE: Record<string, "neutral" | "ok" | "warn"> = {
  active: "ok",
  draft: "warn",
  archived: "neutral",
};

export function TemplateStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <Badge tone={TEMPLATE_TONE[status] ?? "neutral"}>
      {t(`bulletins.templates.status.${status}`, status)}
    </Badge>
  );
}

export function TemplatesPage() {
  const { t } = useTranslation();
  const { slug, can } = useWorkspace();
  const workspace = slug ?? "";
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState<Message>();
  const templates = useQuery({
    queryKey: ["bulletin-templates", workspace],
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletin-templates", {
          params: { path: { workspace } },
        }),
      ),
  });
  const rows = templates.data ?? [];

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const source = rows.find((tpl) => tpl.id === form.get("from"));
    try {
      // A new template starts from a copy of an existing one (its latest version).
      const base = source
        ? unwrap(
            await client.GET("/api/v1/workspaces/{workspace}/bulletin-templates/{template_id}", {
              params: { path: { workspace, template_id: source.id } },
            }),
          )
        : undefined;
      const created = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/bulletin-templates", {
          params: { path: { workspace } },
          body: {
            name: String(form.get("name") ?? ""),
            description: String(form.get("description") ?? ""),
            spec: (base?.latest_spec ?? {}) as Record<string, never>,
            comment: source ? t("bulletins.templates.copiedFrom", { name: source.name }) : "",
          },
        }),
      );
      setCreating(false);
      void navigate(`/bulletin-templates/${created.id}`);
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <>
      <PageHeader
        title={t("bulletins.templates.title", { team: workspace.toUpperCase() })}
        actions={
          can("template.manage") && rows.length ? (
            <Button onClick={() => setCreating(true)}>{t("bulletins.templates.create")}</Button>
          ) : null
        }
      />
      <p className="vv-muted">{t("bulletins.templates.intro")}</p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {templates.isError ? <Alert>{errorMessage(t, templates.error)}</Alert> : null}
      <DataTable<Template>
        rows={rows}
        rowKey={(tpl) => tpl.id}
        empty={templates.isPending ? t("auth.loading") : t("bulletins.templates.empty")}
        columns={[
          {
            key: "name",
            header: t("bulletins.templates.name"),
            render: (tpl) => (
              <>
                <Link to={`/bulletin-templates/${tpl.id}`}>{tpl.name}</Link>
                {tpl.is_default ? (
                  <>
                    {" "}
                    <Badge tone="ok">{t("bulletins.templates.default")}</Badge>
                  </>
                ) : null}
              </>
            ),
          },
          {
            key: "language",
            header: t("bulletins.languageColumn"),
            render: (tpl) => tpl.language?.toUpperCase() ?? "—",
          },
          {
            key: "priority",
            header: t("bulletins.templates.priority"),
            render: (tpl) => tpl.priority ?? "—",
          },
          {
            key: "rules",
            header: t("bulletins.templates.rules"),
            render: (tpl) =>
              tpl.rule_count
                ? t("bulletins.templates.ruleCount", { count: tpl.rule_count })
                : t("bulletins.templates.noRules"),
          },
          { key: "tlp", header: "TLP", render: (tpl) => (tpl.tlp ? `TLP:${tpl.tlp}` : "—") },
          {
            key: "status",
            header: t("bulletins.statusColumn"),
            render: (tpl) => <TemplateStatusBadge status={tpl.status} />,
          },
          {
            key: "version",
            header: t("bulletins.templates.activeVersion"),
            render: (tpl) =>
              tpl.active_version_no
                ? `v${tpl.active_version_no}${tpl.latest_version_no !== tpl.active_version_no ? ` (${t("bulletins.templates.latest", { no: tpl.latest_version_no })})` : ""}`
                : "—",
          },
          {
            key: "updated",
            header: t("bulletins.updated"),
            render: (tpl) => formatDate(tpl.updated_at),
          },
        ]}
      />
      {can("workspace.settings.manage") ? (
        <Settings workspace={workspace} templates={rows} onMessage={setMessage} />
      ) : null}
      <Dialog
        open={creating}
        title={t("bulletins.templates.create")}
        onClose={() => setCreating(false)}
      >
        <form className="vv-form" onSubmit={create}>
          <TextField name="name" label={t("bulletins.templates.name")} required maxLength={200} />
          <TextField
            name="description"
            label={t("bulletins.templates.description")}
            maxLength={2000}
          />
          <div className="vv-field">
            <label htmlFor="vv-template-from">{t("bulletins.templates.from")}</label>
            <select id="vv-template-from" name="from" defaultValue={rows[0]?.id}>
              {rows.map((tpl) => (
                <option key={tpl.id} value={tpl.id}>
                  {tpl.name}
                </option>
              ))}
            </select>
          </div>
          <div className="vv-actions">
            <Button type="submit">{t("bulletins.templates.createSubmit")}</Button>
            <Button variant="secondary" onClick={() => setCreating(false)}>
              {t("common.cancel")}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

/** Reference prefix (Q37), double validation (Q4) and default template of the workspace. */
function Settings({
  workspace,
  templates,
  onMessage,
}: {
  workspace: string;
  templates: Template[];
  onMessage: (message: Message) => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const settings = useQuery({
    queryKey: ["bulletin-settings", workspace],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletin-settings", {
          params: { path: { workspace } },
        }),
      ),
  });
  if (!settings.data) return null;
  return (
    <SettingsForm
      key={settings.data.version}
      settings={settings.data}
      templates={templates}
      onSave={async (body) => {
        try {
          unwrap(
            await client.PUT("/api/v1/workspaces/{workspace}/bulletin-settings", {
              params: { path: { workspace } },
              body,
            }),
          );
          onMessage({ tone: "success", text: t("bulletins.settings.saved") });
          await queryClient.invalidateQueries({ queryKey: ["bulletin-settings", workspace] });
          await queryClient.invalidateQueries({ queryKey: ["bulletin-templates", workspace] });
        } catch (err) {
          onMessage({ tone: "error", text: apiDetail(t, err) });
        }
      }}
    />
  );
}

function SettingsForm({
  settings,
  templates,
  onSave,
}: {
  settings: Schemas["SettingsOut"];
  templates: Template[];
  onSave: (body: Schemas["SettingsIn"]) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [prefix, setPrefix] = useState(settings.ref_prefix);
  const [review, setReview] = useState(settings.review_required);
  const [defaultId, setDefaultId] = useState(settings.default_template_id ?? "");
  const [publisher, setPublisher] = useState(settings.csaf_publisher_name);
  const [namespace, setNamespace] = useState(settings.csaf_publisher_namespace);
  const [category, setCategory] = useState(settings.csaf_publisher_category);
  return (
    <Card title={t("bulletins.settings.title")}>
      <form
        className="vv-form"
        onSubmit={(event) => {
          event.preventDefault();
          void onSave({
            ref_prefix: prefix,
            review_required: review,
            default_template_id: defaultId || null,
            csaf_publisher_name: publisher,
            csaf_publisher_namespace: namespace,
            csaf_publisher_category: category as NonNullable<
              Schemas["SettingsIn"]["csaf_publisher_category"]
            >,
            version: settings.version,
          });
        }}
      >
        <TextField
          label={t("bulletins.settings.prefix")}
          hint={t("bulletins.settings.prefixHint", {
            example: `${prefix}-${new Date().getFullYear()}-0001`,
          })}
          value={prefix}
          pattern="[A-Z][A-Z0-9\-]{0,15}"
          required
          onChange={(e) => setPrefix(e.target.value.toUpperCase())}
        />
        <Checkbox label={t("bulletins.settings.review")} checked={review} onChange={setReview} />
        <p className="vv-muted">{t("bulletins.settings.reviewHint")}</p>
        <SelectField
          label={t("bulletins.settings.defaultTemplate")}
          value={defaultId}
          onChange={setDefaultId}
          options={[
            { value: "", label: "—" },
            ...templates
              .filter((tpl) => tpl.status === "active")
              .map((tpl) => ({ value: tpl.id, label: tpl.name })),
          ]}
        />
        <h3>{t("bulletins.settings.csaf")}</h3>
        <p className="vv-muted">{t("bulletins.settings.csafHint")}</p>
        <TextField
          label={t("bulletins.settings.csafName")}
          value={publisher}
          maxLength={200}
          onChange={(e) => setPublisher(e.target.value)}
        />
        <TextField
          label={t("bulletins.settings.csafNamespace")}
          type="url"
          placeholder="https://"
          pattern="https://.+"
          value={namespace}
          onChange={(e) => setNamespace(e.target.value)}
        />
        <SelectField
          label={t("bulletins.settings.csafCategory")}
          value={category}
          onChange={setCategory}
          options={["coordinator", "discoverer", "other", "translator", "user", "vendor"].map(
            (value) => ({ value, label: t(`bulletins.settings.csafCategories.${value}`) }),
          )}
        />
        <Button type="submit">{t("common.save")}</Button>
      </form>
    </Card>
  );
}
