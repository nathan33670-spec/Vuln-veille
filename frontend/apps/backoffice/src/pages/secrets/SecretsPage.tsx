import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage, useStepUp } from "@vv/auth";
import { Alert, Button, DataTable, Dialog, PageHeader, SelectField, TextField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";

type Secret = Schemas["SecretOut"];
type Purpose = "llm" | "source" | "connector" | "webhook";

/** Write-only: values are typed here, sent once, and never shown again (ADR-013). */
export function SecretsPage({ scope }: { scope: "workspace" | "global" }) {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const workspace = slug ?? "";
  const key = ["secrets", scope, slug];
  const [creating, setCreating] = useState(false);
  const [replacing, setReplacing] = useState<Secret>();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const secrets = useQuery({
    queryKey: key,
    enabled: scope === "global" || Boolean(slug),
    queryFn: async () =>
      scope === "global"
        ? unwrap(await client.GET("/api/v1/admin/secrets"))
        : unwrap(
            await client.GET("/api/v1/workspaces/{workspace}/secrets", {
              params: { path: { workspace } },
            }),
          ),
  });
  const purposes: Purpose[] =
    scope === "global" ? ["source", "llm"] : ["source", "llm", "connector", "webhook"];

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await withStepUp(action);
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  const remove = (s: Secret) =>
    act(
      async () =>
        scope === "global"
          ? unwrap(
              await client.DELETE("/api/v1/admin/secrets/{secret_id}", {
                params: { path: { secret_id: s.id } },
              }),
            )
          : unwrap(
              await client.DELETE("/api/v1/workspaces/{workspace}/secrets/{secret_id}", {
                params: { path: { workspace, secret_id: s.id } },
              }),
            ),
      t("secrets.deleted"),
    );

  return (
    <>
      <PageHeader
        title={
          scope === "global"
            ? t("secrets.globalTitle")
            : t("secrets.title", { team: workspace.toUpperCase() })
        }
        actions={<Button onClick={() => setCreating(true)}>{t("secrets.add")}</Button>}
      />
      <Alert tone="info">{t("secrets.writeOnly")}</Alert>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <DataTable<Secret>
        rows={secrets.data ?? []}
        rowKey={(s) => s.id}
        empty={secrets.isPending ? t("auth.loading") : t("secrets.empty")}
        columns={[
          { key: "name", header: t("admin.name"), render: (s) => s.name },
          {
            key: "purpose",
            header: t("secrets.purpose"),
            render: (s) => t(`secrets.purposes.${s.purpose}`),
          },
          {
            key: "hint",
            header: t("secrets.hint"),
            render: (s) => (s.hint_last4 ? `…${s.hint_last4}` : "—"),
          },
          {
            key: "updated",
            header: t("secrets.updated"),
            render: (s) => formatDate(s.value_updated_at),
          },
          {
            key: "actions",
            header: "",
            render: (s) => (
              <span className="vv-actions">
                <Button variant="secondary" onClick={() => setReplacing(s)}>
                  {t("secrets.replace")}
                </Button>
                <Button variant="danger" onClick={() => remove(s)}>
                  {t("common.remove")}
                </Button>
              </span>
            ),
          },
        ]}
      />
      <Dialog open={creating} title={t("secrets.add")} onClose={() => setCreating(false)}>
        <SecretForm
          purposes={purposes}
          onSubmit={(body) =>
            act(async () => {
              if (scope === "global") unwrap(await client.POST("/api/v1/admin/secrets", { body }));
              else
                unwrap(
                  await client.POST("/api/v1/workspaces/{workspace}/secrets", {
                    params: { path: { workspace } },
                    body,
                  }),
                );
              setCreating(false);
            }, t("secrets.created"))
          }
          onCancel={() => setCreating(false)}
        />
      </Dialog>
      <Dialog
        open={Boolean(replacing)}
        title={t("secrets.replace")}
        onClose={() => setReplacing(undefined)}
      >
        {replacing ? (
          <ValueForm
            onSubmit={(value) =>
              act(async () => {
                const body = { value };
                if (scope === "global")
                  unwrap(
                    await client.PUT("/api/v1/admin/secrets/{secret_id}/value", {
                      params: { path: { secret_id: replacing.id } },
                      body,
                    }),
                  );
                else
                  unwrap(
                    await client.PUT("/api/v1/workspaces/{workspace}/secrets/{secret_id}/value", {
                      params: { path: { workspace, secret_id: replacing.id } },
                      body,
                    }),
                  );
                setReplacing(undefined);
              }, t("secrets.replaced"))
            }
            onCancel={() => setReplacing(undefined)}
          />
        ) : null}
      </Dialog>
    </>
  );
}

function SecretForm({
  purposes,
  onSubmit,
  onCancel,
}: {
  purposes: Purpose[];
  onSubmit: (body: {
    name: string;
    purpose: Purpose;
    description: string;
    value: string;
  }) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState<Purpose>(purposes[0] ?? "source");
  const [description, setDescription] = useState("");
  const [value, setValue] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    await onSubmit({ name, purpose, description, value });
    setValue("");
  }
  return (
    <form className="vv-form" onSubmit={submit} autoComplete="off">
      <TextField
        label={t("admin.name")}
        hint={t("secrets.nameHint")}
        value={name}
        required
        maxLength={64}
        pattern="[a-z0-9][a-z0-9_.\-]{0,63}"
        onChange={(e) => setName(e.target.value)}
      />
      <SelectField
        label={t("secrets.purpose")}
        value={purpose}
        onChange={(v) => setPurpose(v as Purpose)}
        options={purposes.map((p) => ({ value: p, label: t(`secrets.purposes.${p}`) }))}
      />
      <TextField
        label={t("secrets.description")}
        value={description}
        maxLength={500}
        onChange={(e) => setDescription(e.target.value)}
      />
      <TextField
        label={t("secrets.value")}
        type="password"
        autoComplete="new-password"
        value={value}
        required
        maxLength={16384}
        onChange={(e) => setValue(e.target.value)}
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

function ValueForm({
  onSubmit,
  onCancel,
}: {
  onSubmit: (value: string) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [value, setValue] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    await onSubmit(value);
    setValue("");
  }
  return (
    <form className="vv-form" onSubmit={submit} autoComplete="off">
      <TextField
        label={t("secrets.newValue")}
        type="password"
        autoComplete="new-password"
        value={value}
        required
        maxLength={16384}
        onChange={(e) => setValue(e.target.value)}
      />
      <div className="vv-actions">
        <Button type="submit">{t("secrets.replace")}</Button>
        <Button variant="secondary" onClick={onCancel}>
          {t("auth.cancel")}
        </Button>
      </div>
    </form>
  );
}
