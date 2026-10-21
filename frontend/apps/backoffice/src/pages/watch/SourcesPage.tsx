import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  DataTable,
  Dialog,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { splitList } from "../../lib";
import { useWorkspace } from "../../workspace";

type Source = Schemas["WatchSourceOut"];
type Create = Schemas["WatchSourceCreate"];
const TYPES = {
  rss: "url",
  website: "url",
  x_account: "handle",
  github_repo: "repo",
  mastodon_account: "account",
  bluesky_account: "handle",
  subreddit: "name",
} as const;
type SourceType = keyof typeof TYPES;

export function SourcesPage() {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const queryClient = useQueryClient();
  const workspace = slug ?? "";
  const key = ["sources", workspace];
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const sources = useQuery({
    queryKey: key,
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/sources", {
          params: { path: { workspace } },
        }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }
  const item = (s: Source) => ({ params: { path: { workspace, source_id: s.id } } });

  return (
    <>
      <PageHeader
        title={t("sources.title", { team: workspace.toUpperCase() })}
        actions={<Button onClick={() => setCreating(true)}>{t("sources.add")}</Button>}
      />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <DataTable<Source>
        rows={sources.data ?? []}
        rowKey={(s) => s.id}
        empty={sources.isPending ? t("auth.loading") : t("sources.empty")}
        columns={[
          { key: "name", header: t("admin.name"), render: (s) => s.name },
          { key: "type", header: t("sources.type"), render: (s) => t(`sources.types.${s.type}`) },
          {
            key: "target",
            header: t("sources.target"),
            render: (s) => String(Object.entries(s.config).find(([k]) => k !== "type")?.[1] ?? ""),
          },
          {
            key: "tags",
            header: t("sources.tags"),
            render: (s) => (
              <span className="vv-chips">
                {s.tags.map((tag) => (
                  <Badge key={tag}>{tag}</Badge>
                ))}
              </span>
            ),
          },
          {
            key: "trust",
            header: t("sources.trust"),
            render: (s) => t(`sources.trustLevels.${s.trust_level}`),
          },
          {
            key: "actions",
            header: "",
            render: (s) => (
              <span className="vv-actions">
                <Button
                  variant="secondary"
                  onClick={() =>
                    act(
                      async () =>
                        unwrap(
                          await client.PATCH("/api/v1/workspaces/{workspace}/sources/{source_id}", {
                            ...item(s),
                            body: { version: s.version, enabled: !s.enabled },
                          }),
                        ),
                      t("admin.saved"),
                    )
                  }
                >
                  {s.enabled ? t("admin.disable") : t("admin.enable")}
                </Button>
                <Button
                  variant="danger"
                  onClick={() =>
                    act(
                      async () =>
                        unwrap(
                          await client.DELETE(
                            "/api/v1/workspaces/{workspace}/sources/{source_id}",
                            item(s),
                          ),
                        ),
                      t("sources.deleted"),
                    )
                  }
                >
                  {t("common.remove")}
                </Button>
              </span>
            ),
          },
        ]}
      />
      <Dialog open={creating} title={t("sources.add")} onClose={() => setCreating(false)}>
        <SourceForm
          onSubmit={(body) =>
            act(async () => {
              unwrap(
                await client.POST("/api/v1/workspaces/{workspace}/sources", {
                  params: { path: { workspace } },
                  body,
                }),
              );
              setCreating(false);
            }, t("sources.created"))
          }
          onCancel={() => setCreating(false)}
        />
      </Dialog>
    </>
  );
}

function SourceForm({
  onSubmit,
  onCancel,
}: {
  onSubmit: (body: Create) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [type, setType] = useState<SourceType>("rss");
  const [target, setTarget] = useState("");
  const [tags, setTags] = useState("");
  const [trust, setTrust] = useState<"low" | "medium" | "high">("medium");
  async function submit(event: FormEvent) {
    event.preventDefault();
    const config = { type, [TYPES[type]]: target.trim() } as Create["config"];
    await onSubmit({ name, config, tags: splitList(tags), trust_level: trust, enabled: true });
  }
  return (
    <form className="vv-form" onSubmit={submit}>
      <TextField
        label={t("admin.name")}
        value={name}
        required
        maxLength={100}
        onChange={(e) => setName(e.target.value)}
      />
      <SelectField
        label={t("sources.type")}
        value={type}
        onChange={(v) => setType(v as SourceType)}
        options={Object.keys(TYPES).map((k) => ({ value: k, label: t(`sources.types.${k}`) }))}
      />
      <TextField
        label={t(`sources.fields.${TYPES[type]}`)}
        hint={t(`sources.examples.${type}`)}
        value={target}
        required
        onChange={(e) => setTarget(e.target.value)}
      />
      <TextField
        label={t("sources.tags")}
        hint={t("scope.listHint")}
        value={tags}
        onChange={(e) => setTags(e.target.value)}
      />
      <SelectField
        label={t("sources.trust")}
        value={trust}
        onChange={(v) => setTrust(v as "low" | "medium" | "high")}
        options={["low", "medium", "high"].map((v) => ({
          value: v,
          label: t(`sources.trustLevels.${v}`),
        }))}
      />
      <div className="vv-actions">
        <Button type="submit">{t("admin.create")}</Button>
        <Button variant="secondary" onClick={onCancel}>
          {t("auth.cancel")}
        </Button>
      </div>
    </form>
  );
}
