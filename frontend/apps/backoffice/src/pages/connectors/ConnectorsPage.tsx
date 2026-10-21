import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage, useStepUp } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  DataTable,
  Dialog,
  PageHeader,
  SelectField,
  Tabs,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { ConfigForm, type ConfigSchema, type ConfigValues, initialValues } from "./ConfigForm";

type Connector = Schemas["ConnectorOut"];
type ConnectorType = Schemas["ConnectorTypeOut"];
type Family = "source" | "ai_engine" | "publish";
const PURPOSE: Record<Family, string> = {
  source: "source",
  ai_engine: "llm",
  publish: "connector",
};
const HEALTH_TONE = { ok: "ok", degraded: "warn", failing: "error", unknown: "neutral" } as const;

// Every family shares the same request and response schemas: the typed client is given
// the "source" path and the actual family is substituted at run time.
type ListPath = "/api/v1/workspaces/{workspace}/connectors/source";
type ItemPath = "/api/v1/workspaces/{workspace}/connectors/source/{connector_id}";
type CheckPath = "/api/v1/workspaces/{workspace}/connectors/source/{connector_id}/check";

export function ConnectorsPage({ scope }: { scope: "workspace" | "global" }) {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const [family, setFamily] = useState<Family>("source");
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const workspace = slug ?? "";
  const prefix =
    scope === "global" ? "/api/v1/admin/connectors" : `/api/v1/workspaces/{workspace}/connectors`;
  const listPath = `${prefix}/${family}` as ListPath;
  const itemPath = `${prefix}/${family}/{connector_id}` as ItemPath;
  const checkPath = `${prefix}/${family}/{connector_id}/check` as CheckPath;
  const key = ["connectors", scope, workspace, family];

  const types = useQuery({
    queryKey: ["connector-types"],
    queryFn: async () => unwrap(await client.GET("/api/v1/connector-types")),
  });
  const connectors = useQuery({
    queryKey: key,
    enabled: scope === "global" || Boolean(slug),
    queryFn: async () => unwrap(await client.GET(listPath, { params: { path: { workspace } } })),
  });
  const available = (types.data ?? []).filter(
    (ty) => ty.family === family && ty.scopes.includes(scope),
  );

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await withStepUp(action);
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }
  const itemParams = (c: Connector) => ({ params: { path: { workspace, connector_id: c.id } } });

  return (
    <>
      <PageHeader
        title={
          scope === "global"
            ? t("connectors.globalTitle")
            : t("connectors.title", { team: workspace.toUpperCase() })
        }
        actions={
          available.length ? (
            <Button onClick={() => setCreating(true)}>{t("connectors.add")}</Button>
          ) : null
        }
      />
      <Tabs<Family>
        label={t("connectors.family")}
        value={family}
        onChange={setFamily}
        options={[
          { value: "source", label: t("connectors.families.source") },
          { value: "ai_engine", label: t("connectors.families.ai_engine") },
          { value: "publish", label: t("connectors.families.publish") },
        ]}
      />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {connectors.isError ? <Alert>{errorMessage(t, connectors.error)}</Alert> : null}
      <DataTable<Connector>
        rows={connectors.data ?? []}
        rowKey={(c) => c.id}
        empty={
          connectors.isPending
            ? t("auth.loading")
            : available.length
              ? t("connectors.empty")
              : t("connectors.noType")
        }
        columns={[
          { key: "name", header: t("admin.name"), render: (c) => c.name },
          {
            key: "kind",
            header: t("connectors.kind"),
            render: (c) => types.data?.find((ty) => ty.kind === c.kind)?.label ?? c.kind,
          },
          {
            key: "health",
            header: t("connectors.health"),
            render: (c) => (
              <span title={c.last_error ?? ""}>
                <Badge tone={HEALTH_TONE[c.health as keyof typeof HEALTH_TONE] ?? "neutral"}>
                  {t(`connectors.healthStates.${c.health}`)}
                </Badge>
              </span>
            ),
          },
          {
            key: "check",
            header: t("connectors.lastCheck"),
            render: (c) => formatDate(c.last_check_at),
          },
          { key: "error", header: t("connectors.lastError"), render: (c) => c.last_error ?? "—" },
          {
            key: "actions",
            header: "",
            render: (c) => (
              <span className="vv-actions">
                <Button
                  variant="secondary"
                  onClick={() =>
                    act(
                      async () => unwrap(await client.POST(checkPath, itemParams(c))),
                      t("connectors.checkQueued"),
                    )
                  }
                >
                  {t("connectors.check")}
                </Button>
                <Button
                  variant="secondary"
                  onClick={() =>
                    act(
                      async () =>
                        unwrap(
                          await client.PATCH(itemPath, {
                            ...itemParams(c),
                            body: { version: c.version, enabled: !c.enabled },
                          }),
                        ),
                      t("admin.saved"),
                    )
                  }
                >
                  {c.enabled ? t("admin.disable") : t("admin.enable")}
                </Button>
                <Button
                  variant="danger"
                  onClick={() =>
                    act(
                      async () => unwrap(await client.DELETE(itemPath, itemParams(c))),
                      t("connectors.deleted"),
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
      <Dialog open={creating} title={t("connectors.add")} onClose={() => setCreating(false)}>
        <CreateConnector
          types={available}
          scope={scope}
          purpose={PURPOSE[family]}
          onCreate={(body) =>
            act(async () => {
              unwrap(await client.POST(listPath, { params: { path: { workspace } }, body }));
              setCreating(false);
            }, t("connectors.created"))
          }
          onCancel={() => setCreating(false)}
        />
      </Dialog>
    </>
  );
}

function CreateConnector({
  types,
  scope,
  purpose,
  onCreate,
  onCancel,
}: {
  types: ConnectorType[];
  scope: "workspace" | "global";
  purpose: string;
  onCreate: (body: Schemas["ConnectorCreate"]) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const { slug } = useWorkspace();
  const [kind, setKind] = useState(types[0]?.kind ?? "");
  const type = types.find((ty) => ty.kind === kind);
  const schema = (type?.config_schema ?? {}) as ConfigSchema;
  const [name, setName] = useState(type?.label ?? "");
  const [values, setValues] = useState<ConfigValues>(() => initialValues(schema));
  const [refs, setRefs] = useState<Record<string, string>>({});
  const secrets = useQuery({
    queryKey: ["secrets", scope, slug],
    queryFn: async () =>
      scope === "global"
        ? unwrap(await client.GET("/api/v1/admin/secrets"))
        : unwrap(
            await client.GET("/api/v1/workspaces/{workspace}/secrets", {
              params: { path: { workspace: slug ?? "" } },
            }),
          ),
  });
  const candidates = (secrets.data ?? []).filter((s) => s.purpose === purpose);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const secret_refs = Object.fromEntries(Object.entries(refs).filter(([, v]) => v));
    await onCreate({ kind, name, config: values, secret_refs, enabled: true });
  }

  return (
    <form className="vv-form" onSubmit={submit}>
      <SelectField
        label={t("connectors.kind")}
        value={kind}
        onChange={(value) => {
          const next = types.find((ty) => ty.kind === value);
          setKind(value);
          setName(next?.label ?? "");
          setValues(initialValues((next?.config_schema ?? {}) as ConfigSchema));
          setRefs({});
        }}
        options={types.map((ty) => ({
          value: ty.kind,
          label: `${ty.label} (${t(`connectors.cost.${ty.cost_class}`)})`,
        }))}
      />
      <TextField
        label={t("admin.name")}
        value={name}
        required
        maxLength={100}
        onChange={(e) => setName(e.target.value)}
      />
      {type ? (
        <p className="vv-muted">
          {t("connectors.domains", { domains: type.egress_domains.join(", ") || "—" })}
        </p>
      ) : null}
      <ConfigForm schema={schema} values={values} onChange={setValues} />
      {(type?.secret_slots ?? []).map((slot) => (
        <SelectField
          key={slot.name}
          label={`${slot.label}${slot.required ? " *" : ""}`}
          value={refs[slot.name] ?? ""}
          onChange={(value) => setRefs({ ...refs, [slot.name]: value })}
          options={[
            { value: "", label: candidates.length ? "—" : t("connectors.noSecret") },
            ...candidates.map((s) => ({ value: s.id, label: s.name })),
          ]}
        />
      ))}
      <Card>
        <p className="vv-muted">{t("connectors.secretHint")}</p>
      </Card>
      <div className="vv-actions">
        <Button type="submit" disabled={!type}>
          {t("admin.create")}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          {t("auth.cancel")}
        </Button>
      </div>
    </form>
  );
}
