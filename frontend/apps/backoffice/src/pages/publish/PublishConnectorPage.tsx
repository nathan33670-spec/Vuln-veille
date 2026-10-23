import { ApiError, type Schemas, unwrap } from "@vv/api-client";
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
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useNavigate, useParams } from "react-router";

import { client } from "../../api";
import { formatDate } from "../../lib";
import { useWorkspace } from "../../workspace";
import { apiDetail } from "../ai/shared";
import {
  AUTH_TYPES,
  type AuthType,
  defaultConfig,
  numbers,
  type PublishConfig,
  PushJournal,
  PushStatusBadge,
  REQUIRED_SLOTS,
  usePush,
  withDefaults,
} from "./shared";

type Scope = "workspace" | "global";
type Connector = Schemas["ConnectorOut"];
type Message = { tone: "error" | "success" | "info"; text: string };
const SLOTS = [
  "credential",
  "username",
  "password",
  "client_id",
  "client_secret",
  "client_certificate",
  "client_key",
  "signing_key",
  "ca_bundle",
];
const METHODS = ["POST", "PUT", "PATCH"].map((m) => ({ value: m, label: m }));
const PREVIEW_DELAY_MS = 700;

function headersText(headers: Record<string, string>): string {
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const at = line.indexOf(":");
    if (at > 0) out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return out;
}

/** The configuration as sent: unused optional parts left out. */
function cleaned(config: PublishConfig, mapping: unknown): Record<string, unknown> {
  return {
    ...config,
    auth: {
      ...config.auth,
      endpoint_url:
        config.auth.type === "oauth2_client_credentials" ? config.auth.endpoint_url : null,
    },
    body: {
      format: config.body.format,
      mapping: config.body.format === "json" ? mapping : null,
    },
  };
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="vv-fieldset">
      <legend>{title}</legend>
      {children}
    </fieldset>
  );
}

export function PublishConnectorPage({ scope }: { scope: Scope }) {
  const { t } = useTranslation();
  const { id } = useParams();
  const { slug } = useWorkspace();
  const workspace = slug ?? "";
  const creating = !id || id === "new";
  const connector = useQuery({
    queryKey: ["publish-connector", scope, workspace, id],
    enabled: !creating && (scope === "global" || Boolean(slug)),
    queryFn: async () =>
      scope === "global"
        ? unwrap(
            await client.GET("/api/v1/admin/connectors/publish/{connector_id}", {
              params: { path: { connector_id: id ?? "" } },
            }),
          )
        : unwrap(
            await client.GET("/api/v1/workspaces/{workspace}/connectors/publish/{connector_id}", {
              params: { path: { workspace, connector_id: id ?? "" } },
            }),
          ),
  });
  if (!creating && connector.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (connector.isError) return <Alert>{errorMessage(t, connector.error)}</Alert>;
  return (
    <Editor
      key={connector.data ? `${connector.data.id}-${connector.data.version}` : "new"}
      scope={scope}
      workspace={workspace}
      connector={connector.data}
    />
  );
}

function Editor({
  scope,
  workspace,
  connector,
}: {
  scope: Scope;
  workspace: string;
  connector: Connector | undefined;
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const [name, setName] = useState(connector?.name ?? "");
  const [enabled, setEnabled] = useState(connector?.enabled ?? true);
  const [config, setConfig] = useState<PublishConfig>(() =>
    connector ? withDefaults(connector.config) : defaultConfig(),
  );
  const [mappingText, setMappingText] = useState(() =>
    JSON.stringify(config.body.mapping ?? {}, null, 2),
  );
  const [headers, setHeaders] = useState(() => headersText(config.request.headers));
  const [refs, setRefs] = useState<Record<string, string>>(() =>
    Object.fromEntries(Object.entries(connector?.secret_refs ?? {}).map(([k, v]) => [k, v])),
  );
  const location = useLocation();
  const [message, setMessage] = useState<Message | undefined>(() =>
    (location.state as { saved?: boolean } | null)?.saved
      ? { tone: "success", text: t("publish.editor.saved") }
      : undefined,
  );
  const [errors, setErrors] = useState<string[]>([]);
  const base = scope === "global" ? "/admin/publish-connectors" : "/publish-connectors";

  const mapping = useMemo(() => {
    try {
      return JSON.parse(mappingText) as unknown;
    } catch {
      return undefined;
    }
  }, [mappingText]);
  const full = useMemo(
    () =>
      cleaned(
        { ...config, request: { ...config.request, headers: parseHeaders(headers) } },
        mapping,
      ),
    [config, headers, mapping],
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
  const connectorSecrets = (secrets.data ?? []).filter((s) => s.purpose === "connector");
  const required = REQUIRED_SLOTS[config.auth.type];
  const update = config.request.update;

  const set = <K extends keyof PublishConfig>(key: K, value: Partial<PublishConfig[K]>) =>
    setConfig((previous) => ({
      ...previous,
      [key]:
        typeof previous[key] === "object" && previous[key] !== null
          ? { ...(previous[key] as object), ...(value as object) }
          : value,
    }));

  async function save(event: FormEvent) {
    event.preventDefault();
    if (mapping === undefined && config.body.format === "json") {
      setErrors([t("publish.editor.invalidJson")]);
      return;
    }
    const secretRefs = Object.fromEntries(Object.entries(refs).filter(([, v]) => v));
    try {
      const saved = await withStepUp(async () => {
        if (!connector) {
          const body = {
            kind: "http_generic",
            name,
            config: full,
            secret_refs: secretRefs,
            enabled,
          };
          return scope === "global"
            ? unwrap(await client.POST("/api/v1/admin/connectors/publish", { body }))
            : unwrap(
                await client.POST("/api/v1/workspaces/{workspace}/connectors/publish", {
                  params: { path: { workspace } },
                  body,
                }),
              );
        }
        const body = {
          version: connector.version,
          name,
          config: full,
          secret_refs: secretRefs,
          enabled,
        };
        const path = { connector_id: connector.id };
        return scope === "global"
          ? unwrap(
              await client.PATCH("/api/v1/admin/connectors/publish/{connector_id}", {
                params: { path },
                body,
              }),
            )
          : unwrap(
              await client.PATCH(
                "/api/v1/workspaces/{workspace}/connectors/publish/{connector_id}",
                { params: { path: { ...path, workspace } }, body },
              ),
            );
      });
      setErrors([]);
      setMessage({ tone: "success", text: t("publish.editor.saved") });
      await queryClient.invalidateQueries({ queryKey: ["publish-connector"] });
      await queryClient.invalidateQueries({ queryKey: ["publish-targets"] });
      // The new connector's page carries the confirmation (the editor is remounted).
      if (!connector) void navigate(`${base}/${saved.id}`, { state: { saved: true } });
    } catch (err) {
      if (err instanceof ApiError && err.errors.length) {
        setErrors(
          err.errors.map((e) => {
            const raw = e as unknown as {
              loc?: unknown[];
              type?: string;
              path?: string;
              code?: string;
            };
            return `${(raw.loc ?? [raw.path]).join(".")} : ${raw.type ?? raw.code ?? ""}`;
          }),
        );
      }
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <>
      <PageHeader
        title={connector ? connector.name : t("publish.editor.newTitle")}
        actions={
          <Link to={scope === "global" ? "/admin/connectors" : "/publish-connectors"}>
            {t("publish.editor.back")}
          </Link>
        }
      />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <form className="vv-form" onSubmit={save}>
        <Section title={t("publish.editor.general")}>
          <TextField
            label={t("publish.editor.name")}
            value={name}
            required
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
          />
          <Checkbox label={t("publish.editor.enabled")} checked={enabled} onChange={setEnabled} />
        </Section>

        <Section title={t("publish.editor.request")}>
          <TextField
            label={t("publish.editor.baseUrl")}
            hint={t("publish.editor.baseUrlHint")}
            value={config.request.base_url}
            required
            onChange={(e) => set("request", { base_url: e.target.value })}
          />
          <div className="vv-filters">
            <SelectField
              label={t("publish.editor.method")}
              value={config.request.method}
              onChange={(v) => set("request", { method: v as PublishConfig["request"]["method"] })}
              options={METHODS}
            />
            <TextField
              label={t("publish.editor.path")}
              hint={t("publish.editor.pathHint")}
              value={config.request.path}
              onChange={(e) => set("request", { path: e.target.value })}
            />
          </div>
          <Checkbox
            label={t("publish.editor.update")}
            checked={config.request.update !== null}
            onChange={(on) =>
              set("request", {
                update: on
                  ? {
                      method: "PUT",
                      path: `${config.request.path.replace(/\/$/, "")}/{{ remote_id }}`,
                    }
                  : null,
              })
            }
          />
          {update ? (
            <div className="vv-filters">
              <SelectField
                label={t("publish.editor.updateMethod")}
                value={update.method}
                onChange={(v) =>
                  set("request", {
                    update: { ...update, method: v as "POST" | "PUT" | "PATCH" },
                  })
                }
                options={METHODS}
              />
              <TextField
                label={t("publish.editor.updatePath")}
                value={update.path}
                onChange={(e) => set("request", { update: { ...update, path: e.target.value } })}
              />
            </div>
          ) : null}
          <TextArea
            label={t("publish.editor.headers")}
            hint={t("publish.editor.headersHint")}
            className="vv-textarea vv-mono"
            rows={3}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
          />
          <div className="vv-filters">
            <TextField
              label={t("publish.editor.timeout")}
              type="number"
              min={1}
              max={60}
              value={config.request.timeout_seconds}
              onChange={(e) => set("request", { timeout_seconds: Number(e.target.value) })}
            />
            <TextField
              label={t("publish.editor.healthPath")}
              hint={t("publish.editor.healthPathHint")}
              value={config.request.health_path}
              onChange={(e) => set("request", { health_path: e.target.value })}
            />
          </div>
        </Section>

        <Section title={t("publish.editor.auth")}>
          <SelectField
            label={t("publish.editor.authType")}
            value={config.auth.type}
            onChange={(v) => set("auth", { type: v as AuthType })}
            options={AUTH_TYPES.map((v) => ({ value: v, label: t(`publish.auth.${v}`) }))}
          />
          <AuthFields config={config} set={(v) => set("auth", v)} />
          {[...required, ...SLOTS.filter((s) => s === "ca_bundle")].map((slot) => (
            <SelectField
              key={slot}
              label={`${t(`publish.slots.${slot}`)}${required.includes(slot) ? " *" : ""}`}
              value={refs[slot] ?? ""}
              onChange={(v) => setRefs((previous) => ({ ...previous, [slot]: v }))}
              options={[
                { value: "", label: "—" },
                ...connectorSecrets.map((s) => ({ value: s.id, label: s.name })),
              ]}
            />
          ))}
          <p className="vv-muted">
            {t("publish.editor.secretsHint")}{" "}
            <Link to={scope === "global" ? "/admin/secrets" : "/secrets"}>
              {t("publish.editor.secretsLink")}
            </Link>
          </p>
        </Section>

        <Section title={t("publish.editor.body")}>
          <SelectField
            label={t("publish.editor.format")}
            value={config.body.format}
            onChange={(v) => set("body", { format: v as PublishConfig["body"]["format"] })}
            options={["json", "csaf", "markdown"].map((v) => ({
              value: v,
              label: t(`publish.formats.${v}`),
            }))}
          />
          {config.body.format === "json" ? (
            <TextArea
              label={t("publish.editor.mapping")}
              hint={t("publish.editor.mappingHint")}
              className="vv-textarea vv-mono"
              rows={16}
              spellCheck={false}
              value={mappingText}
              onChange={(e) => setMappingText(e.target.value)}
            />
          ) : null}
          {mapping === undefined && config.body.format === "json" ? (
            <Alert>{t("publish.editor.invalidJson")}</Alert>
          ) : null}
        </Section>

        <Section title={t("publish.editor.response")}>
          <div className="vv-filters">
            <TextField
              label={t("publish.editor.successStatus")}
              value={config.response.success_status.join(", ")}
              onChange={(e) => set("response", { success_status: numbers(e.target.value) })}
            />
            <TextField
              label={t("publish.editor.remoteIdPath")}
              hint={t("publish.editor.remoteIdHint")}
              value={config.response.remote_id_path}
              onChange={(e) => set("response", { remote_id_path: e.target.value })}
            />
            <TextField
              label={t("publish.editor.idempotency")}
              value={config.idempotency_header}
              onChange={(e) => setConfig((c) => ({ ...c, idempotency_header: e.target.value }))}
            />
          </div>
        </Section>

        <Section title={t("publish.editor.retries")}>
          <div className="vv-filters">
            <TextField
              label={t("publish.editor.maxAttempts")}
              type="number"
              min={1}
              max={8}
              value={config.retry.max_attempts}
              onChange={(e) => set("retry", { max_attempts: Number(e.target.value) })}
            />
            <TextField
              label={t("publish.editor.backoff")}
              value={config.retry.backoff_seconds.join(", ")}
              onChange={(e) => set("retry", { backoff_seconds: numbers(e.target.value) })}
            />
            <TextField
              label={t("publish.editor.retryOn")}
              value={config.retry.retry_on.join(", ")}
              onChange={(e) => set("retry", { retry_on: numbers(e.target.value) })}
            />
            <TextField
              label={t("publish.editor.rateLimit")}
              type="number"
              min={1}
              max={600}
              value={config.rate_limit_per_minute}
              onChange={(e) =>
                setConfig((c) => ({ ...c, rate_limit_per_minute: Number(e.target.value) }))
              }
            />
          </div>
          <Checkbox
            label={t("publish.editor.retryNetwork")}
            checked={config.retry.retry_network}
            onChange={(v) => set("retry", { retry_network: v })}
          />
        </Section>

        {errors.length ? (
          <Alert>
            <ul>
              {errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </Alert>
        ) : null}
        <Button type="submit">{connector ? t("common.save") : t("publish.editor.create")}</Button>
      </form>
      <Preview workspace={workspace} config={full} />
      {connector ? <Operations scope={scope} workspace={workspace} connector={connector} /> : null}
    </>
  );
}

function AuthFields({
  config,
  set,
}: {
  config: PublishConfig;
  set: (value: Partial<PublishConfig["auth"]>) => void;
}) {
  const { t } = useTranslation();
  const auth = config.auth;
  switch (auth.type) {
    case "api_key":
      return (
        <div className="vv-filters">
          <SelectField
            label={t("publish.editor.keyLocation")}
            value={auth.key_location}
            onChange={(v) => set({ key_location: v as "header" | "query" })}
            options={[
              { value: "header", label: t("publish.editor.inHeader") },
              { value: "query", label: t("publish.editor.inQuery") },
            ]}
          />
          <TextField
            label={t("publish.editor.keyName")}
            value={auth.key_name}
            onChange={(e) => set({ key_name: e.target.value })}
          />
        </div>
      );
    case "oauth2_client_credentials":
      return (
        <div className="vv-filters">
          <TextField
            label={t("publish.editor.endpointUrl")}
            value={auth.endpoint_url ?? ""}
            required
            onChange={(e) => set({ endpoint_url: e.target.value })}
          />
          <TextField
            label={t("publish.editor.scope")}
            value={auth.scope}
            onChange={(e) => set({ scope: e.target.value })}
          />
          <TextField
            label={t("publish.editor.audience")}
            value={auth.audience}
            onChange={(e) => set({ audience: e.target.value })}
          />
        </div>
      );
    case "hmac":
      return (
        <div className="vv-filters">
          <SelectField
            label={t("publish.editor.algorithm")}
            value={auth.algorithm}
            onChange={(v) => set({ algorithm: v as "sha256" | "sha512" })}
            options={[
              { value: "sha256", label: "HMAC-SHA256" },
              { value: "sha512", label: "HMAC-SHA512" },
            ]}
          />
          <TextField
            label={t("publish.editor.signedHeader")}
            value={auth.signed_header}
            onChange={(e) => set({ signed_header: e.target.value })}
          />
          <TextField
            label={t("publish.editor.digestPrefix")}
            value={auth.digest_prefix}
            onChange={(e) => set({ digest_prefix: e.target.value })}
          />
          <SelectField
            label={t("publish.editor.encoding")}
            value={auth.encoding}
            onChange={(v) => set({ encoding: v as "hex" | "base64" })}
            options={[
              { value: "hex", label: "hex" },
              { value: "base64", label: "base64" },
            ]}
          />
          <TextField
            label={t("publish.editor.timestampHeader")}
            hint={t("publish.editor.timestampHint")}
            value={auth.timestamp_header}
            onChange={(e) => set({ timestamp_header: e.target.value })}
          />
        </div>
      );
    default:
      return null;
  }
}

/** Payload and exact request computed by the server, on a validated bulletin or the
 * example, while the configuration is being edited. */
function Preview({ workspace, config }: { workspace: string; config: Record<string, unknown> }) {
  const { t } = useTranslation();
  const [bulletinId, setBulletinId] = useState("");
  const [preview, setPreview] = useState<Schemas["MappingPreviewOut"]>();
  const [error, setError] = useState<string>();
  const bulletins = useQuery({
    queryKey: ["pushable-bulletins", workspace],
    queryFn: async () => {
      const lists = await Promise.all(
        ["approved", "published"].map(async (status) =>
          unwrap(
            await client.GET("/api/v1/workspaces/{workspace}/bulletins", {
              params: { path: { workspace }, query: { status, scope: "own" } },
            }),
          ),
        ),
      );
      return lists.flat();
    },
  });
  useEffect(() => {
    const timer = window.setTimeout(async () => {
      try {
        setPreview(
          unwrap(
            await client.POST("/api/v1/workspaces/{workspace}/publish-mapping/preview", {
              params: { path: { workspace } },
              body: { config, bulletin_id: bulletinId || null },
            }),
          ),
        );
        setError(undefined);
      } catch (err) {
        setError(apiDetail(t, err));
      }
    }, PREVIEW_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [workspace, config, bulletinId, t]);

  return (
    <Card title={t("publish.preview.title")}>
      <SelectField
        label={t("publish.preview.on")}
        value={bulletinId}
        onChange={setBulletinId}
        options={[
          { value: "", label: t("publish.preview.example") },
          ...(bulletins.data ?? []).map((b) => ({ value: b.id, label: `${b.ref} — ${b.title}` })),
        ]}
      />
      {error ? <Alert>{error}</Alert> : null}
      {preview && !preview.valid ? (
        <Alert>
          <ul>
            {preview.errors.map((e, i) => (
              <li key={i}>{JSON.stringify(e)}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      {preview?.payload !== undefined && preview?.payload !== null ? (
        <>
          <h3>{t("publish.preview.payload")}</h3>
          <pre className="vv-pre" aria-label={t("publish.preview.payload")}>
            {JSON.stringify(preview.payload, null, 2)}
          </pre>
        </>
      ) : null}
      {preview?.request ? (
        <>
          <h3>{t("publish.preview.request")}</h3>
          <pre className="vv-pre">
            {`${preview.request.method} ${preview.request.url}\n${Object.entries(
              preview.request.headers,
            )
              .map(([k, v]) => `${k}: ${v}`)
              .join("\n")}\n\n${preview.request.body}`}
          </pre>
        </>
      ) : (
        <p className="vv-muted">{t("publish.preview.requestHint")}</p>
      )}
      {preview?.paths.length ? (
        <details>
          <summary>{t("publish.preview.paths")}</summary>
          <ul className="vv-mono">
            {preview.paths.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </Card>
  );
}

function Operations({
  scope,
  workspace,
  connector,
}: {
  scope: Scope;
  workspace: string;
  connector: Connector;
}) {
  const { t } = useTranslation();
  const [testId, setTestId] = useState<string>();
  const [message, setMessage] = useState<Message>();
  const test = usePush(workspace, testId);

  async function sendTest() {
    try {
      const queued = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/publish-targets/{connector_id}/test", {
          params: { path: { workspace, connector_id: connector.id } },
        }),
      );
      setTestId(queued.id);
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <>
      <Card title={t("publish.test.title")}>
        <p className="vv-muted">{t("publish.test.hint")}</p>
        <Button variant="secondary" onClick={() => void sendTest()}>
          {t("publish.test.send")}
        </Button>
        {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
        {test ? (
          <p role="status">
            <PushStatusBadge status={test.status} />{" "}
            {test.response_status ? `HTTP ${test.response_status}` : ""} {test.error ?? ""}
          </p>
        ) : null}
      </Card>
      <Card title={t("publish.journal.title")}>
        <PushJournal workspace={workspace} connectorId={connector.id} />
      </Card>
      {scope === "workspace" ? (
        <PrivateNetwork workspace={workspace} connector={connector} />
      ) : null}
    </>
  );
}

function PrivateNetwork({ workspace, connector }: { workspace: string; connector: Connector }) {
  const { t } = useTranslation();
  const withStepUp = useStepUp();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<Message>();
  const path = { workspace, connector_id: connector.id };
  const key = ["private-network", workspace, connector.id];
  const requests = useQuery({
    queryKey: key,
    queryFn: async () =>
      unwrap(
        await client.GET(
          "/api/v1/workspaces/{workspace}/connectors/publish/{connector_id}/private-network",
          { params: { path } },
        ),
      ),
  });

  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await withStepUp(async () =>
        unwrap(
          await client.POST(
            "/api/v1/workspaces/{workspace}/connectors/publish/{connector_id}/private-network",
            {
              params: { path },
              body: {
                cidrs: String(form.get("cidrs") ?? "")
                  .split(/[\s,]+/)
                  .filter(Boolean),
                reason: String(form.get("reason") ?? ""),
              },
            },
          ),
        ),
      );
      setMessage({ tone: "success", text: t("publish.network.requested") });
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  return (
    <Card title={t("publish.network.title")}>
      <p className="vv-muted">{t("publish.network.hint")}</p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <ul className="vv-change-list">
        {(requests.data ?? []).map((r) => (
          <li key={r.id}>
            <Badge
              tone={r.status === "approved" ? "ok" : r.status === "pending" ? "warn" : "neutral"}
            >
              {t(`publish.network.status.${r.status}`, r.status)}
            </Badge>{" "}
            {r.cidrs.join(", ")} · {formatDate(r.requested_at)} · {r.reason}
            {r.decision_note ? ` · ${r.decision_note}` : ""}
          </li>
        ))}
      </ul>
      <form className="vv-form" onSubmit={request}>
        <TextField
          name="cidrs"
          label={t("publish.network.cidrs")}
          placeholder="10.20.0.0/16"
          required
        />
        <TextArea
          name="reason"
          label={t("publish.network.reason")}
          rows={2}
          required
          maxLength={1000}
        />
        <Button type="submit" variant="secondary">
          {t("publish.network.submit")}
        </Button>
      </form>
    </Card>
  );
}
