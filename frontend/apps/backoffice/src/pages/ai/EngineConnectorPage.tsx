import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage, useStepUp } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  PageHeader,
  SelectField,
  TextArea,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useNavigate, useParams } from "react-router";

import { client } from "../../api";
import { useWorkspace } from "../../workspace";
import {
  ConfigForm,
  type ConfigSchema,
  type ConfigValues,
  initialValues,
} from "../connectors/ConfigForm";
import { PrivateNetwork } from "../connectors/PrivateNetwork";
import { apiDetail } from "./shared";

type Scope = "workspace" | "global";
type Connector = Schemas["ConnectorOut"];
type ConnectorType = Schemas["ConnectorTypeOut"];
type Message = { tone: "error" | "success" | "info"; text: string };

const DATA_CLASSES = ["public", "tlp_clear", "tlp_green", "tlp_amber", "tlp_red"] as const;
const TOOLS = ["native", "emulated", "none"] as const;
const STRUCTURED = ["native", "guided_json", "none"] as const;
// Lists are edited below; the generated form only gets the scalar settings.
const LISTS = new Set(["models", "data_classes"]);
const PROBE_POLL_MS = 1000;

interface ModelRow {
  model_id: string;
  display_name: string;
  enabled: boolean;
  tools: (typeof TOOLS)[number];
  structured_output: (typeof STRUCTURED)[number];
  context_window: number;
  max_output_tokens: number;
  [extra: string]: unknown;
}

const newModel = (): ModelRow => ({
  model_id: "",
  display_name: "",
  enabled: true,
  tools: "emulated",
  structured_output: "none",
  context_window: 32000,
  max_output_tokens: 4096,
});

function scalarSchema(schema: ConfigSchema, labels: Record<string, string>): ConfigSchema {
  const properties = Object.fromEntries(
    Object.entries(schema.properties ?? {})
      .filter(([name]) => !LISTS.has(name))
      .map(([name, property]) => {
        const title = labels[name];
        return [name, title ? { ...property, title } : property];
      }),
  );
  return { ...schema, properties };
}

// The typed client is given the workspace "ai_engine" paths; the global ones share
// the same schemas.
type ListPath = "/api/v1/workspaces/{workspace}/connectors/ai_engine";
type ItemPath = "/api/v1/workspaces/{workspace}/connectors/ai_engine/{connector_id}";
type ProbePath = "/api/v1/workspaces/{workspace}/connectors/ai_engine/{connector_id}/probe";
type ProbeItemPath =
  "/api/v1/workspaces/{workspace}/connectors/ai_engine/{connector_id}/probe/{probe_id}";

function paths(scope: Scope) {
  const prefix =
    scope === "global"
      ? "/api/v1/admin/connectors/ai_engine"
      : "/api/v1/workspaces/{workspace}/connectors/ai_engine";
  return {
    list: prefix as ListPath,
    item: `${prefix}/{connector_id}` as ItemPath,
    probe: `${prefix}/{connector_id}/probe` as ProbePath,
    probeItem: `${prefix}/{connector_id}/probe/{probe_id}` as ProbeItemPath,
  };
}

/** Declares an AI engine (OpenAI-compatible server, Gemini, Claude) with its models,
 * asks for its private range when it is self-hosted, and asks its model a question. */
export function EngineConnectorPage({ scope }: { scope: Scope }) {
  const { t } = useTranslation();
  const { id } = useParams();
  const { slug } = useWorkspace();
  const workspace = slug ?? "";
  const creating = !id || id === "new";
  const connector = useQuery({
    queryKey: ["engine-connector", scope, workspace, id],
    enabled: !creating && (scope === "global" || Boolean(slug)),
    queryFn: async () =>
      unwrap(
        await client.GET(paths(scope).item, {
          params: { path: { workspace, connector_id: id ?? "" } },
        }),
      ),
  });
  const types = useQuery({
    queryKey: ["connector-types"],
    queryFn: async () => unwrap(await client.GET("/api/v1/connector-types")),
  });
  if ((!creating && connector.isPending) || types.isPending)
    return <p className="vv-muted">{t("auth.loading")}</p>;
  if (connector.isError) return <Alert>{errorMessage(t, connector.error)}</Alert>;
  const available = (types.data ?? []).filter(
    (ty) => ty.family === "ai_engine" && ty.scopes.includes(scope),
  );
  return (
    <>
      <Editor
        key={connector.data ? `${connector.data.id}-${connector.data.version}` : "new"}
        scope={scope}
        workspace={workspace}
        connector={connector.data}
        types={available}
      />
      {connector.data ? (
        <>
          <Probe scope={scope} workspace={workspace} connector={connector.data} />
          {scope === "workspace" ? (
            <PrivateNetwork
              family="ai_engine"
              workspace={workspace}
              connectorId={connector.data.id}
            />
          ) : null}
        </>
      ) : null}
    </>
  );
}

function Editor({
  scope,
  workspace,
  connector,
  types,
}: {
  scope: Scope;
  workspace: string;
  connector: Connector | undefined;
  types: ConnectorType[];
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const [kind, setKind] = useState(
    connector?.kind ??
      types.find((ty) => ty.kind === "openai_compatible")?.kind ??
      types[0]?.kind ??
      "",
  );
  const type = types.find((ty) => ty.kind === kind);
  const schema = (type?.config_schema ?? {}) as ConfigSchema;
  const current = connector?.config;
  const [name, setName] = useState(connector?.name ?? t("ai.engines.defaultName"));
  const [values, setValues] = useState<ConfigValues>(() => initialValues(schema, current));
  const [classes, setClasses] = useState<string[]>(
    (current?.data_classes as string[] | undefined) ?? ["public", "tlp_clear"],
  );
  const [models, setModels] = useState<ModelRow[]>(
    (current?.models as ModelRow[] | undefined) ?? [newModel()],
  );
  const [refs, setRefs] = useState<Record<string, string>>(
    (connector?.secret_refs as Record<string, string> | undefined) ?? {},
  );
  const [message, setMessage] = useState<Message | undefined>(
    (location.state as { saved?: boolean } | null)?.saved
      ? { tone: "success", text: t("ai.engines.saved") }
      : undefined,
  );
  const secrets = useQuery({
    queryKey: ["secrets", scope, workspace],
    queryFn: async () =>
      scope === "global"
        ? unwrap(await client.GET("/api/v1/admin/secrets"))
        : unwrap(
            await client.GET("/api/v1/workspaces/{workspace}/secrets", {
              params: { path: { workspace } },
            }),
          ),
  });
  const candidates = (secrets.data ?? []).filter((s) => s.purpose === "llm");
  const labels = {
    base_url: t("ai.engines.baseUrl"),
    location: t("ai.engines.location"),
    timeout_seconds: t("ai.engines.timeout"),
  };
  const setModel = (index: number, change: Partial<ModelRow>) =>
    setModels(models.map((m, i) => (i === index ? { ...m, ...change } : m)));

  async function save(event: FormEvent) {
    event.preventDefault();
    const config = { ...values, data_classes: classes, models };
    const secret_refs = Object.fromEntries(Object.entries(refs).filter(([, v]) => v));
    const p = paths(scope);
    try {
      const saved = await withStepUp(async () =>
        connector
          ? unwrap(
              await client.PATCH(p.item, {
                params: { path: { workspace, connector_id: connector.id } },
                body: { version: connector.version, name, config, secret_refs },
              }),
            )
          : unwrap(
              await client.POST(p.list, {
                params: { path: { workspace } },
                body: { kind, name, config, secret_refs, enabled: true },
              }),
            ),
      );
      setMessage({ tone: "success", text: t("ai.engines.saved") });
      await queryClient.invalidateQueries({ queryKey: ["engine-connector"] });
      await queryClient.invalidateQueries({ queryKey: ["ai-models"] });
      const base = scope === "global" ? "/admin/ai-engines" : "/ai-engines";
      if (!connector) void navigate(`${base}/${saved.id}`, { state: { saved: true } });
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <>
      <p>
        <Link to={scope === "global" ? "/admin/connectors" : "/connectors"}>
          {t("ai.engines.back")}
        </Link>
      </p>
      <PageHeader title={connector ? connector.name : t("ai.engines.new")} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {!types.length ? <Alert>{t("connectors.noType")}</Alert> : null}
      <form className="vv-form" onSubmit={save}>
        <Card title={t("ai.engines.server")}>
          <SelectField
            label={t("connectors.kind")}
            value={kind}
            onChange={(value) => {
              const next = types.find((ty) => ty.kind === value);
              setKind(value);
              setValues(initialValues((next?.config_schema ?? {}) as ConfigSchema));
              setRefs({});
            }}
            options={types.map((ty) => ({ value: ty.kind, label: ty.label }))}
          />
          <TextField
            label={t("admin.name")}
            value={name}
            required
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
          />
          <ConfigForm schema={scalarSchema(schema, labels)} values={values} onChange={setValues} />
          {kind === "openai_compatible" ? (
            <p className="vv-muted">{t("ai.engines.localHint")}</p>
          ) : null}
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
        </Card>
        <Card title={t("ai.engines.dataClasses")}>
          <p className="vv-muted">{t("ai.engines.dataClassesHint")}</p>
          {DATA_CLASSES.map((c) => (
            <Checkbox
              key={c}
              label={t(`ai.engines.classes.${c}`)}
              checked={classes.includes(c)}
              onChange={(on) => setClasses(on ? [...classes, c] : classes.filter((x) => x !== c))}
            />
          ))}
        </Card>
        <Card title={t("ai.engines.models")}>
          {models.map((m, index) => (
            <fieldset className="vv-fieldset" key={index}>
              <legend>{m.model_id || t("ai.engines.newModel")}</legend>
              <TextField
                label={t("ai.engines.modelId")}
                hint={t("ai.engines.modelIdHint")}
                value={m.model_id}
                required
                maxLength={128}
                onChange={(e) => setModel(index, { model_id: e.target.value.trim() })}
              />
              <TextField
                label={t("ai.engines.displayName")}
                value={m.display_name}
                maxLength={100}
                onChange={(e) => setModel(index, { display_name: e.target.value })}
              />
              <SelectField
                label={t("ai.engines.tools")}
                value={m.tools}
                onChange={(v) => setModel(index, { tools: v as ModelRow["tools"] })}
                options={TOOLS.map((v) => ({ value: v, label: t(`ai.engines.toolModes.${v}`) }))}
              />
              <SelectField
                label={t("ai.engines.structured")}
                value={m.structured_output}
                onChange={(v) =>
                  setModel(index, { structured_output: v as ModelRow["structured_output"] })
                }
                options={STRUCTURED.map((v) => ({
                  value: v,
                  label: t(`ai.engines.structuredModes.${v}`),
                }))}
              />
              <TextField
                label={t("ai.engines.contextWindow")}
                type="number"
                min={1024}
                value={m.context_window}
                onChange={(e) => setModel(index, { context_window: Number(e.target.value) })}
              />
              <TextField
                label={t("ai.engines.maxOutput")}
                type="number"
                min={256}
                value={m.max_output_tokens}
                onChange={(e) => setModel(index, { max_output_tokens: Number(e.target.value) })}
              />
              <Checkbox
                label={t("ai.engines.modelEnabled")}
                checked={m.enabled}
                onChange={(on) => setModel(index, { enabled: on })}
              />
              {models.length > 1 ? (
                <Button
                  variant="secondary"
                  onClick={() => setModels(models.filter((_, i) => i !== index))}
                >
                  {t("ai.engines.removeModel")}
                </Button>
              ) : null}
            </fieldset>
          ))}
          <div className="vv-actions">
            <Button variant="secondary" onClick={() => setModels([...models, newModel()])}>
              {t("ai.engines.addModel")}
            </Button>
          </div>
        </Card>
        <div className="vv-actions">
          <Button type="submit" disabled={!type}>
            {connector ? t("ai.engines.save") : t("ai.engines.create")}
          </Button>
        </div>
      </form>
    </>
  );
}

function Probe({
  scope,
  workspace,
  connector,
}: {
  scope: Scope;
  workspace: string;
  connector: Connector;
}) {
  const { t } = useTranslation();
  const models = ((connector.config.models as ModelRow[] | undefined) ?? []).filter(
    (m) => m.enabled,
  );
  const [model, setModel] = useState(models[0]?.model_id ?? "");
  const [prompt, setPrompt] = useState(t("ai.engines.probeDefault"));
  const [probeId, setProbeId] = useState<string>();
  const [error, setError] = useState<string>();
  const p = paths(scope);
  const result = useQuery({
    queryKey: ["engine-probe", connector.id, probeId],
    enabled: Boolean(probeId),
    queryFn: async () =>
      unwrap(
        await client.GET(p.probeItem, {
          params: {
            path: { workspace, connector_id: connector.id, probe_id: probeId ?? "" },
          },
        }),
      ),
    refetchInterval: (query) =>
      ["succeeded", "failed"].includes(query.state.data?.status ?? "") ? false : PROBE_POLL_MS,
  });

  async function ask(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    try {
      const queued = unwrap(
        await client.POST(p.probe, {
          params: { path: { workspace, connector_id: connector.id } },
          body: { model_id: model, prompt },
        }),
      );
      setProbeId(queued.probe_id);
    } catch (err) {
      setError(apiDetail(t, err));
    }
  }

  const r = result.data;
  const running = Boolean(probeId) && (!r || r.status === "queued" || r.status === "running");
  const failure = r?.status === "failed" ? (r.error ?? "") : "";
  return (
    <Card title={t("ai.engines.probe")}>
      <p className="vv-muted">{t("ai.engines.probeHint")}</p>
      {error ? <Alert>{error}</Alert> : null}
      <form className="vv-form" onSubmit={ask}>
        <SelectField
          label={t("ai.engines.probeModel")}
          value={model}
          onChange={setModel}
          options={models.map((m) => ({ value: m.model_id, label: m.display_name || m.model_id }))}
        />
        <TextArea
          label={t("ai.engines.probePrompt")}
          value={prompt}
          rows={3}
          maxLength={4000}
          required
          onChange={(e) => setPrompt(e.target.value)}
        />
        <div className="vv-actions">
          <Button type="submit" disabled={!model || running}>
            {running ? t("ai.engines.probeRunning") : t("ai.engines.probeSend")}
          </Button>
        </div>
      </form>
      {r?.status === "succeeded" ? (
        <div role="status">
          <p>
            <Badge tone="ok">{t("ai.engines.probeOk")}</Badge>{" "}
            <span className="vv-muted">
              {t("ai.engines.probeMeta", {
                model: r.model_served,
                input: r.input_tokens,
                output: r.output_tokens,
                ms: r.duration_ms,
              })}
            </span>
          </p>
          {/* The answer is untrusted text: shown as text, never as HTML. */}
          <pre className="vv-pre" aria-label={t("ai.engines.probeAnswer")}>
            {r.answer}
          </pre>
        </div>
      ) : null}
      {failure ? (
        <Alert>
          {t("ai.engines.probeFailed", { error: failure })}
          {failure.startsWith("egress:") ? ` ${t("ai.engines.probeEgressHint")}` : ""}
        </Alert>
      ) : null}
    </Card>
  );
}
