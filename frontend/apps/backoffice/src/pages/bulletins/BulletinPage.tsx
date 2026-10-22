import { ApiError, type Schemas, unwrap } from "@vv/api-client";
import { errorMessage, useMe, useStepUp } from "@vv/auth";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Dialog,
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
import { apiDetail } from "../ai/shared";
import { lineDiff } from "../workflows/editor/diff";
import {
  type BulletinDetail,
  BulletinSeverity,
  BulletinStatusBadge,
  type DraftRequest,
  followDraft,
  fromEditor,
  isJsonField,
  type TemplateField,
  templateFields,
  TLPS,
  TlpBadge,
  toEditor,
} from "./shared";

type Message = { tone: "error" | "success" | "info"; text: string };
type Values = Record<string, string | boolean>;
const PREVIEW_DELAY_MS = 600;

function editorValues(fields: TemplateField[], values: Record<string, unknown>): Values {
  return Object.fromEntries(fields.map((f) => [f.key, toEditor(f, values[f.key])]));
}

/** Editor values back to field values; the keys of JSON fields that do not parse. */
function fieldValues(fields: TemplateField[], values: Values) {
  const out: Record<string, unknown> = {};
  const invalid: string[] = [];
  for (const f of fields) {
    const value = fromEditor(f, values[f.key] ?? "");
    if (value === undefined) invalid.push(f.key);
    else out[f.key] = value;
  }
  return { out, invalid };
}

export function BulletinPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const { slug, can } = useWorkspace();
  const me = useMe().data;
  const workspace = slug ?? "";
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const key = ["bulletin", workspace, id];
  const [message, setMessage] = useState<Message>();
  const bulletin = useQuery({
    queryKey: key,
    enabled: Boolean(slug),
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}", {
          params: { path: { workspace, bulletin_id: id } },
        }),
      ),
  });

  async function refresh() {
    await queryClient.invalidateQueries({ queryKey: key });
    await queryClient.invalidateQueries({ queryKey: ["bulletins", workspace] });
  }

  async function act(action: () => Promise<unknown>, success: string, stepUp = false) {
    try {
      await (stepUp ? withStepUp(action) : action());
      setMessage({ tone: "success", text: success });
      await refresh();
      return true;
    } catch (err) {
      setMessage({ tone: "error", text: apiDetail(t, err) });
      return false;
    }
  }

  if (bulletin.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (bulletin.isError) return <Alert>{errorMessage(t, bulletin.error)}</Alert>;
  const b = bulletin.data;
  const editable = b.own && b.status !== "withdrawn" && can("bulletin.draft");

  return (
    <>
      <PageHeader
        title={`${b.ref} — ${b.title}`}
        actions={<Link to="/bulletins">{t("bulletins.back")}</Link>}
      />
      <p className="vv-actions">
        <BulletinStatusBadge status={b.status} />
        <TlpBadge tlp={b.tlp} />
        <BulletinSeverity severity={b.severity} />
        <span>{t(`bulletins.language.${b.language}`)}</span>
        {b.template_name ? (
          <span className="vv-muted">
            {t("bulletins.templateUsed", { name: b.template_name, version: b.template_version_no })}
          </span>
        ) : null}
        {!b.own ? (
          <span className="vv-muted">
            {t("bulletins.sharedFrom", { team: b.workspace_slug.toUpperCase() })}
          </span>
        ) : null}
      </p>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      {b.own && b.published_rev_no && b.status !== "published" && b.status !== "withdrawn" ? (
        <Alert tone="info">
          {t("bulletins.publishedStillVisible", { rev: b.published_rev_no })}
        </Alert>
      ) : null}
      {b.status === "withdrawn" && b.withdrawn_reason ? (
        <Alert tone="info">{t("bulletins.withdrawnBecause", { reason: b.withdrawn_reason })}</Alert>
      ) : null}
      {b.own ? (
        <Workflow
          bulletin={b}
          userId={me?.id ?? ""}
          can={can}
          act={act}
          workspace={workspace}
          onMessage={setMessage}
          onDone={refresh}
        />
      ) : null}
      <Links bulletin={b} />
      {editable && b.current && b.template_spec ? (
        <Editor
          key={`${b.current.rev_no}-${b.tlp}`}
          bulletin={b}
          workspace={workspace}
          onSaved={refresh}
          onMessage={setMessage}
        />
      ) : b.current ? (
        <Card title={t("bulletins.content", { rev: b.current.rev_no })}>
          <SafeHtml className="vv-bulletin" html={b.current.rendered_html} />
        </Card>
      ) : null}
      {b.own && editable ? <Marking bulletin={b} workspace={workspace} act={act} /> : null}
      {b.own && b.revisions.length ? <Revisions bulletin={b} workspace={workspace} /> : null}
    </>
  );
}

function Links({ bulletin: b }: { bulletin: BulletinDetail }) {
  const { t } = useTranslation();
  if (
    !b.vulnerabilities.length &&
    !b.translation_of &&
    !b.translations.length &&
    !b.technologies.length
  )
    return null;
  return (
    <dl className="vv-kv">
      {b.vulnerabilities.length ? (
        <>
          <dt>{t("bulletins.vulnerabilities")}</dt>
          <dd>
            {b.vulnerabilities.map((v, i) => (
              <span key={v.id}>
                {i ? ", " : ""}
                <Link to={`/vulnerabilities/${v.ref}`}>{v.cve_id ?? v.ref}</Link>
              </span>
            ))}
          </dd>
        </>
      ) : null}
      {b.technologies.length ? (
        <>
          <dt>{t("bulletins.technologies")}</dt>
          <dd>{b.technologies.map((tech) => tech.display_name).join(", ")}</dd>
        </>
      ) : null}
      {b.translation_of ? (
        <>
          <dt>{t("bulletins.translationOf")}</dt>
          <dd>
            <Link to={`/bulletins/${b.translation_of.id}`}>{b.translation_of.ref}</Link>
          </dd>
        </>
      ) : null}
      {b.translations.length ? (
        <>
          <dt>{t("bulletins.translations")}</dt>
          <dd>
            {b.translations.map((tr, i) => (
              <span key={tr.id}>
                {i ? ", " : ""}
                <Link to={`/bulletins/${tr.id}`}>
                  {tr.ref} ({tr.language.toUpperCase()})
                </Link>
              </span>
            ))}
          </dd>
        </>
      ) : null}
    </dl>
  );
}

// --- Review, validation, publication ----------------------------------------------

function Workflow({
  bulletin: b,
  userId,
  can,
  act,
  workspace,
  onMessage,
  onDone,
}: {
  bulletin: BulletinDetail;
  userId: string;
  can: (permission: string) => boolean;
  act: (action: () => Promise<unknown>, success: string, stepUp?: boolean) => Promise<boolean>;
  workspace: string;
  onMessage: (message: Message) => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [withdrawing, setWithdrawing] = useState(false);
  const [translating, setTranslating] = useState<DraftRequest>();
  const path = { workspace, bulletin_id: b.id };
  const body = { version: b.version, comment: "" };
  const transition = (
    action: "submit" | "reject" | "approve" | "publish",
    success: string,
    stepUp = false,
  ) =>
    act(
      async () => {
        const options = { params: { path }, body };
        switch (action) {
          case "submit":
            return unwrap(
              await client.POST(
                "/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/submit",
                options,
              ),
            );
          case "reject":
            return unwrap(
              await client.POST(
                "/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/reject",
                options,
              ),
            );
          case "approve":
            return unwrap(
              await client.POST(
                "/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/approve",
                options,
              ),
            );
          case "publish":
            return unwrap(
              await client.POST(
                "/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/publish",
                options,
              ),
            );
        }
      },
      success,
      stepUp,
    );
  // Double validation: neither the author nor the one who submitted may approve.
  const ownWork = b.review_required && (b.author_id === userId || b.submitted_by === userId);
  const other = b.language === "fr" ? "en" : "fr";
  const translationRequestId = translating?.id;

  useEffect(() => {
    if (!translationRequestId) return;
    return followDraft(workspace, translationRequestId, (request) => {
      setTranslating(request);
      if (request.status === "succeeded") void onDone();
    });
  }, [workspace, translationRequestId, onDone]);

  async function translate() {
    try {
      const request = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/translations", {
          params: { path },
          body: { language: other },
        }),
      );
      setTranslating(request);
    } catch (err) {
      onMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  async function withdraw(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const reason = String(new FormData(event.currentTarget).get("reason") ?? "");
    const done = await act(
      async () =>
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/withdraw", {
            params: { path },
            body: { reason, version: b.version },
          }),
        ),
      t("bulletins.withdrawn"),
      true,
    );
    if (done) setWithdrawing(false);
  }

  const buttons = [];
  if (b.status === "draft" && b.review_required && can("bulletin.draft"))
    buttons.push(
      <Button key="submit" onClick={() => void transition("submit", t("bulletins.submitted"))}>
        {t("bulletins.actions.submit")}
      </Button>,
    );
  if (
    can("bulletin.review") &&
    ((b.status === "draft" && !b.review_required) || b.status === "in_review")
  )
    buttons.push(
      <Button
        key="approve"
        disabled={ownWork}
        title={ownWork ? t("bulletins.reviewerMustDiffer") : undefined}
        onClick={() => void transition("approve", t("bulletins.approved"))}
      >
        {t("bulletins.actions.approve")}
      </Button>,
    );
  if (b.status === "in_review" && can("bulletin.review"))
    buttons.push(
      <Button
        key="reject"
        variant="secondary"
        onClick={() => void transition("reject", t("bulletins.rejected"))}
      >
        {t("bulletins.actions.reject")}
      </Button>,
    );
  if (b.status === "approved" && can("bulletin.publish"))
    buttons.push(
      <Button
        key="publish"
        onClick={() => void transition("publish", t("bulletins.published"), true)}
      >
        {t("bulletins.actions.publish")}
      </Button>,
    );
  if (
    (b.status === "approved" || b.status === "published") &&
    can("bulletin.draft") &&
    !b.translation_of
  )
    buttons.push(
      <Button
        key="translate"
        variant="secondary"
        onClick={() => void translate()}
        disabled={Boolean(translating && translating.status !== "failed")}
      >
        {t("bulletins.actions.translate", { language: t(`bulletins.language.${other}`) })}
      </Button>,
    );
  if (b.published_rev_no && b.status !== "withdrawn" && can("bulletin.publish"))
    buttons.push(
      <Button key="withdraw" variant="danger" onClick={() => setWithdrawing(true)}>
        {t("bulletins.actions.withdraw")}
      </Button>,
    );

  return (
    <>
      {b.status === "in_review" && ownWork ? (
        <Alert tone="info">{t("bulletins.waitingForReviewer")}</Alert>
      ) : null}
      {buttons.length ? <div className="vv-actions">{buttons}</div> : null}
      {translating ? (
        translating.status === "failed" ? (
          <Alert>{t("bulletins.translationFailed")}</Alert>
        ) : translating.status === "succeeded" && translating.bulletin_id ? (
          <Alert tone="success">
            {t("bulletins.translationReady")}{" "}
            <Link to={`/bulletins/${translating.bulletin_id}`}>{t("bulletins.open")}</Link>
          </Alert>
        ) : (
          <p role="status">{t("bulletins.translating")}</p>
        )
      ) : null}
      <Dialog
        open={withdrawing}
        title={t("bulletins.actions.withdraw")}
        onClose={() => setWithdrawing(false)}
      >
        <form className="vv-form" onSubmit={withdraw}>
          <TextArea
            name="reason"
            label={t("bulletins.withdrawReason")}
            required
            maxLength={1000}
            rows={3}
          />
          <div className="vv-actions">
            <Button type="submit" variant="danger">
              {t("bulletins.actions.withdraw")}
            </Button>
            <Button variant="secondary" onClick={() => setWithdrawing(false)}>
              {t("common.cancel")}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

// --- Fields and preview -----------------------------------------------------------

function Editor({
  bulletin: b,
  workspace,
  onSaved,
  onMessage,
}: {
  bulletin: BulletinDetail;
  workspace: string;
  onSaved: () => Promise<void>;
  onMessage: (message: Message) => void;
}) {
  const { t } = useTranslation();
  const spec = useMemo(() => b.template_spec ?? {}, [b.template_spec]);
  const fields = useMemo(() => templateFields(spec), [spec]);
  const current = b.current;
  const [values, setValues] = useState<Values>(() => editorValues(fields, current?.fields ?? {}));
  const [note, setNote] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [draftPreview, setPreview] = useState<string>();
  const [previewError, setPreviewError] = useState<string>();
  const [regenerating, setRegenerating] = useState<TemplateField>();
  const dirty = useMemo(
    () => JSON.stringify(values) !== JSON.stringify(editorValues(fields, current?.fields ?? {})),
    [values, fields, current],
  );

  // The preview is rendered by the server, with the same rules as the bulletin.
  useEffect(() => {
    if (!dirty) return;
    const { out, invalid } = fieldValues(fields, values);
    if (invalid.length) return;
    const timer = window.setTimeout(async () => {
      try {
        const rendered = unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/bulletin-templates/preview", {
            params: { path: { workspace } },
            body: {
              spec,
              fields: out,
              tlp: b.tlp as NonNullable<Schemas["app__bulletins__schemas__PreviewIn"]["tlp"]>,
            },
          }),
        );
        setPreview(rendered.html);
        setPreviewError(undefined);
      } catch (err) {
        setPreviewError(apiDetail(t, err));
      }
    }, PREVIEW_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [dirty, values, fields, spec, workspace, b.tlp, current, t]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const { out, invalid } = fieldValues(fields, values);
    if (invalid.length) {
      setErrors(Object.fromEntries(invalid.map((k) => [k, t("bulletins.errors.json")])));
      return;
    }
    try {
      unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/revisions", {
          params: { path: { workspace, bulletin_id: b.id } },
          body: { fields: out, change_note: note, base_rev_no: current?.rev_no ?? 0 },
        }),
      );
      setErrors({});
      onMessage({ tone: "success", text: t("bulletins.saved") });
      await onSaved();
    } catch (err) {
      if (err instanceof ApiError && err.errors.length) {
        setErrors(
          Object.fromEntries(
            err.errors.map((e) => [
              e.path.replace(/^fields\./, ""),
              t(`bulletins.errors.${e.code}`, e.code),
            ]),
          ),
        );
      }
      onMessage({ tone: "error", text: apiDetail(t, err) });
    }
  }

  const set = (field: string, value: string | boolean) =>
    setValues((previous) => ({ ...previous, [field]: value }));

  return (
    <div className="vv-grid-2">
      <Card title={t("bulletins.fields", { rev: current?.rev_no ?? 0 })}>
        <form className="vv-form" onSubmit={save}>
          {fields.map((f) => (
            <FieldInput
              key={f.key}
              field={f}
              value={values[f.key] ?? ""}
              error={errors[f.key]}
              onChange={(value) => set(f.key, value)}
              onRegenerate={
                f.generation?.mode === "ai" && !dirty ? () => setRegenerating(f) : undefined
              }
            />
          ))}
          <TextField
            label={t("bulletins.changeNote")}
            value={note}
            maxLength={500}
            onChange={(e) => setNote(e.target.value)}
          />
          {b.status !== "draft" ? (
            <p className="vv-muted">{t("bulletins.editResetsReview")}</p>
          ) : null}
          <div className="vv-actions">
            <Button type="submit" disabled={!dirty}>
              {t("bulletins.saveRevision")}
            </Button>
            {dirty ? (
              <Button
                variant="secondary"
                onClick={() => setValues(editorValues(fields, current?.fields ?? {}))}
              >
                {t("bulletins.discard")}
              </Button>
            ) : null}
          </div>
        </form>
      </Card>
      <Card title={dirty ? t("bulletins.previewUnsaved") : t("bulletins.preview")}>
        {dirty && previewError ? <Alert>{previewError}</Alert> : null}
        <SafeHtml
          className="vv-bulletin"
          html={(dirty ? draftPreview : undefined) ?? current?.rendered_html ?? ""}
        />
      </Card>
      {regenerating ? (
        <Regenerate
          field={regenerating}
          bulletin={b}
          workspace={workspace}
          onClose={() => setRegenerating(undefined)}
          onDone={async () => {
            setRegenerating(undefined);
            onMessage({ tone: "success", text: t("bulletins.regenerated") });
            await onSaved();
          }}
        />
      ) : null}
    </div>
  );
}

function FieldInput({
  field: f,
  value,
  error,
  onChange,
  onRegenerate,
}: {
  field: TemplateField;
  value: string | boolean;
  error: string | undefined;
  onChange: (value: string | boolean) => void;
  onRegenerate: (() => void) | undefined;
}) {
  const { t } = useTranslation();
  const label = `${f.label || f.key}${f.required ? " *" : ""}`;
  const mode = f.generation?.mode ?? "manual";
  const hint = [
    t(`bulletins.mode.${mode}`),
    isJsonField(f) ? t("bulletins.jsonHint") : f.type === "list" ? t("bulletins.listHint") : "",
  ]
    .filter(Boolean)
    .join(" · ");
  let input;
  if (f.type === "boolean") {
    input = <Checkbox label={label} checked={Boolean(value)} onChange={onChange} />;
  } else if (f.type === "enum") {
    input = (
      <SelectField
        label={label}
        value={String(value)}
        onChange={onChange}
        options={[
          ...(f.required ? [] : [{ value: "", label: "—" }]),
          ...(f.options ?? []).map((o) => ({ value: o, label: t(`bulletins.severity.${o}`, o) })),
        ]}
      />
    );
  } else if (f.type === "text" || f.type === "date") {
    input = (
      <TextField
        label={label}
        type={f.type === "date" ? "date" : "text"}
        value={String(value)}
        maxLength={f.max_length ?? undefined}
        hint={hint}
        error={error}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  } else {
    input = (
      <TextArea
        label={label}
        value={String(value)}
        rows={isJsonField(f) || f.type === "markdown" ? 6 : 3}
        maxLength={f.max_length ?? undefined}
        hint={hint}
        className={isJsonField(f) ? "vv-textarea vv-mono" : "vv-textarea"}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  return (
    <div>
      {input}
      {error && f.type !== "text" && f.type !== "date" ? (
        <span className="vv-field-error">{error}</span>
      ) : null}
      {onRegenerate ? (
        <Button variant="secondary" onClick={onRegenerate}>
          {t("bulletins.regenerate", { field: f.label || f.key })}
        </Button>
      ) : null}
    </div>
  );
}

function Regenerate({
  field,
  bulletin: b,
  workspace,
  onClose,
  onDone,
}: {
  field: TemplateField;
  bulletin: BulletinDetail;
  workspace: string;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [request, setRequest] = useState<DraftRequest>();
  const [error, setError] = useState<string>();
  const requestId = request?.id;
  useEffect(() => {
    if (!requestId) return;
    return followDraft(workspace, requestId, (update) => {
      setRequest(update);
      if (update.status === "succeeded") void onDone();
    });
  }, [workspace, requestId, onDone]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const instructions = String(new FormData(event.currentTarget).get("instructions") ?? "");
    try {
      setRequest(
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/regenerate", {
            params: { path: { workspace, bulletin_id: b.id } },
            body: { field: field.key, instructions },
          }),
        ),
      );
    } catch (err) {
      setError(apiDetail(t, err));
    }
  }

  return (
    <Dialog
      open
      title={t("bulletins.regenerate", { field: field.label || field.key })}
      onClose={onClose}
    >
      {request ? (
        request.status === "failed" ? (
          <Alert>
            {t("bulletins.draft.failed")} :{" "}
            {t(`bulletins.draft.error.${request.error ?? "internal_error"}`, request.error ?? "")}
          </Alert>
        ) : (
          <p role="status">{t("bulletins.regenerating")}</p>
        )
      ) : (
        <form className="vv-form" onSubmit={submit}>
          <TextArea
            name="instructions"
            label={t("bulletins.draft.instructions")}
            rows={3}
            maxLength={2000}
          />
          {error ? <Alert>{error}</Alert> : null}
          <p className="vv-muted">{t("bulletins.draft.aiNotice")}</p>
          <Button type="submit">{t("bulletins.regenerateSubmit")}</Button>
        </form>
      )}
      <Button variant="secondary" onClick={onClose}>
        {t("common.cancel")}
      </Button>
    </Dialog>
  );
}

// --- Marking and audience ---------------------------------------------------------

function Marking({
  bulletin: b,
  workspace,
  act,
}: {
  bulletin: BulletinDetail;
  workspace: string;
  act: (action: () => Promise<unknown>, success: string) => Promise<boolean>;
}) {
  const { t } = useTranslation();
  const [tlp, setTlp] = useState(b.tlp);
  const [audience, setAudience] = useState(b.audience_type);
  const [orgs, setOrgs] = useState<string[]>(b.audience_org_ids);
  const organizations = useQuery({
    queryKey: ["bulletin-audiences", workspace],
    enabled: audience === "selected",
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletin-audiences", {
          params: { path: { workspace } },
        }),
      ),
  });
  const changed =
    tlp !== b.tlp ||
    audience !== b.audience_type ||
    JSON.stringify([...orgs].sort()) !== JSON.stringify([...b.audience_org_ids].sort());

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(
      async () =>
        unwrap(
          await client.PATCH("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}", {
            params: { path: { workspace, bulletin_id: b.id } },
            body: {
              tlp: tlp !== b.tlp ? tlp : null,
              audience_type: audience,
              audience_org_ids: audience === "selected" ? orgs : [],
              version: b.version,
            },
          }),
        ),
      t("bulletins.markingSaved"),
    );
  }

  return (
    <Card title={t("bulletins.marking")}>
      <form className="vv-form" onSubmit={save}>
        <SelectField
          label={t("bulletins.tlp")}
          value={tlp}
          onChange={setTlp}
          options={TLPS.map((value) => ({ value, label: `TLP:${value}` }))}
        />
        <SelectField
          label={t("bulletins.audience")}
          value={audience}
          onChange={setAudience}
          options={[
            { value: "all_clients", label: t("bulletins.audienceAll") },
            { value: "selected", label: t("bulletins.audienceSelected") },
          ]}
        />
        {audience === "selected" ? (
          <fieldset>
            <legend>{t("bulletins.organizations")}</legend>
            {(organizations.data ?? []).map((o) => (
              <Checkbox
                key={o.id}
                label={o.name}
                checked={orgs.includes(o.id)}
                onChange={(checked) =>
                  setOrgs((previous) =>
                    checked ? [...previous, o.id] : previous.filter((x) => x !== o.id),
                  )
                }
              />
            ))}
            {organizations.data?.length === 0 ? (
              <p className="vv-muted">{t("bulletins.noOrganizations")}</p>
            ) : null}
          </fieldset>
        ) : null}
        {tlp !== b.tlp ? <p className="vv-muted">{t("bulletins.tlpNewRevision")}</p> : null}
        <Button type="submit" disabled={!changed}>
          {t("common.save")}
        </Button>
      </form>
    </Card>
  );
}

// --- Revisions --------------------------------------------------------------------

function Revisions({ bulletin: b, workspace }: { bulletin: BulletinDetail; workspace: string }) {
  const { t } = useTranslation();
  const latest = b.revisions[0]?.rev_no ?? 1;
  const [from, setFrom] = useState(String(Math.max(1, latest - 1)));
  const [to, setTo] = useState(String(latest));
  const revision = (no: string) => ({
    queryKey: ["bulletin-revision", workspace, b.id, no],
    queryFn: async () =>
      unwrap(
        await client.GET(
          "/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/revisions/{rev_no}",
          {
            params: { path: { workspace, bulletin_id: b.id, rev_no: Number(no) } },
          },
        ),
      ),
    enabled: b.revisions.length > 1,
  });
  const before = useQuery(revision(from));
  const after = useQuery(revision(to));
  const lines = useMemo(
    () =>
      before.data && after.data
        ? lineDiff(before.data.rendered_markdown, after.data.rendered_markdown)
        : [],
    [before.data, after.data],
  );
  const options = b.revisions.map((r) => ({ value: String(r.rev_no), label: `r${r.rev_no}` }));

  return (
    <Card title={t("bulletins.revisions")}>
      <ol reversed className="vv-change-list">
        {b.revisions.map((r) => (
          <li key={r.rev_no}>
            <strong>r{r.rev_no}</strong> · {t(`bulletins.by.${r.created_by_type}`)} ·{" "}
            {formatDate(r.created_at)}
            {r.change_note ? ` · ${r.change_note}` : ""}
            {r.rev_no === b.published_rev_no ? ` · ${t("bulletins.publishedRevision")}` : ""}
            {r.agent_run_id ? (
              <>
                {" "}
                · <Link to={`/agent-runs/${r.agent_run_id}`}>{t("bulletins.trace")}</Link>
              </>
            ) : null}
          </li>
        ))}
      </ol>
      {b.revisions.length > 1 ? (
        <>
          <div className="vv-filters">
            <SelectField
              label={t("bulletins.compareFrom")}
              value={from}
              onChange={setFrom}
              options={options}
            />
            <SelectField
              label={t("bulletins.compareTo")}
              value={to}
              onChange={setTo}
              options={options}
            />
          </div>
          <pre className="vv-pre vv-json-diff" aria-label={t("bulletins.diff")}>
            {lines.map((line, i) => (
              <div
                key={i}
                className={line.op === "+" ? "vv-diff-add" : line.op === "-" ? "vv-diff-del" : ""}
              >
                {line.op} {line.text}
              </div>
            ))}
          </pre>
        </>
      ) : null}
    </Card>
  );
}
