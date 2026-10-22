import type { Schemas } from "@vv/api-client";
import { Button, Checkbox, SelectField, TextArea, TextField } from "@vv/ui";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { splitList } from "../../../lib";
import { ExpressionField, type Item } from "./ExpressionField";
import type { GraphNode, LocatedError, NodeSettings, NodeType } from "./model";
import { dynamicText, type FieldSpec, fieldsOf } from "./schema";

type Connector = Schemas["ConnectorOut"];
type Agent = Schemas["AgentOut"];

/** Workspace objects a parameter can point to; null when the analyst cannot list them. */
export interface Choices {
  connectors: Connector[] | null;
  agents: Agent[] | null;
}

/** Where expressions are previewed: the workspace, and the node's sample item if any. */
export interface PreviewContext {
  workspace: string;
  sample: Item | undefined;
}

/** Parameters of the selected node, generated from its type's JSON Schema. */
export function ParamsPanel({
  node,
  type,
  errors,
  choices,
  preview,
  readOnly,
  onChange,
  onDelete,
}: {
  node: GraphNode;
  type: NodeType | undefined;
  errors: LocatedError[];
  choices: Choices;
  preview: PreviewContext;
  readOnly: boolean;
  /** `field` groups successive edits of one field into a single undo step. */
  onChange: (node: GraphNode, field: string) => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const fields = type ? fieldsOf(type.params_schema, type.reference_fields) : [];
  const fieldError = (name: string | null) => {
    const found = errors.find((e) => e.field === name);
    return found ? t(`workflows.graphErrors.${found.code}`, found.code) : undefined;
  };
  const setParam = (name: string, value: unknown) => {
    const params = Object.fromEntries(Object.entries(node.params).filter(([k]) => k !== name));
    if (value !== undefined) params[name] = value;
    onChange({ ...node, params }, `params.${name}`);
  };
  const settings = node.settings ?? {};
  const setSettings = (next: NodeSettings, field: string) =>
    onChange({ ...node, settings: { ...settings, ...next } }, `settings.${field}`);
  const other = errors.filter(
    (e) => e.field !== null && e.field !== "name" && !fields.some((f) => f.name === e.field),
  );

  return (
    <fieldset
      className="vv-editor-panel"
      disabled={readOnly}
      aria-label={t("workflows.editor.params")}
    >
      <h2 className="vv-card-title">{type?.label ?? node.type}</h2>
      <p className="vv-muted">
        <code>{node.type}</code> · <code>{node.id}</code>
      </p>
      {type ? null : (
        <p className="vv-field-error">{t("workflows.graphErrors.unknown_node_type")}</p>
      )}
      {fieldError(null) ? <p className="vv-field-error">{fieldError(null)}</p> : null}
      <TextField
        label={t("workflows.editor.name")}
        value={node.name ?? ""}
        maxLength={120}
        error={fieldError("name")}
        onChange={(e) => onChange({ ...node, name: e.target.value }, "name")}
      />
      {fields.map((field) => (
        <Field
          key={field.name}
          field={field}
          value={node.params[field.name]}
          error={fieldError(field.name)}
          choices={choices}
          preview={preview}
          onChange={(value) => setParam(field.name, value)}
        />
      ))}
      {other.map((e) => (
        <p key={`${e.field}:${e.code}`} className="vv-field-error">
          <code>{e.field}</code> : {t(`workflows.graphErrors.${e.code}`, e.code)}
        </p>
      ))}
      {type && type.category !== "trigger" ? (
        <details>
          <summary>{t("workflows.editor.settings")}</summary>
          <SelectField
            label={t("workflows.editor.onError")}
            value={settings.on_error ?? "stop"}
            onChange={(v) => setSettings({ on_error: v as NodeSettings["on_error"] }, "on_error")}
            options={["stop", "continue", "route"].map((v) => ({
              value: v,
              label: t(`workflows.editor.onErrorModes.${v}`),
            }))}
          />
          <NumberInput
            label={t("workflows.editor.attempts")}
            value={settings.retry?.max_attempts}
            min={1}
            max={10}
            onChange={(v) =>
              setSettings({ retry: { ...settings.retry, max_attempts: v } }, "attempts")
            }
          />
          <NumberInput
            label={t("workflows.editor.timeout")}
            value={settings.timeout_seconds}
            min={1}
            max={3600}
            onChange={(v) => setSettings({ timeout_seconds: v }, "timeout")}
          />
        </details>
      ) : null}
      {readOnly ? null : (
        <div className="vv-actions">
          <Button variant="danger" onClick={onDelete}>
            {t("workflows.editor.deleteNode")}
          </Button>
        </div>
      )}
    </fieldset>
  );
}

function NumberInput({
  label,
  value,
  min,
  max,
  integer = true,
  hint,
  error,
  required,
  onChange,
}: {
  label: string;
  value: unknown;
  min?: number | undefined;
  max?: number | undefined;
  integer?: boolean;
  hint?: string | undefined;
  error?: string | undefined;
  required?: boolean;
  onChange: (value: number | undefined) => void;
}) {
  return (
    <TextField
      label={label}
      type="number"
      value={typeof value === "number" ? String(value) : ""}
      min={min}
      max={max}
      step={integer ? 1 : "any"}
      required={required}
      hint={hint}
      error={error}
      onChange={(e) => onChange(e.target.value === "" ? undefined : Number(e.target.value))}
    />
  );
}

function Field({
  field,
  value,
  error,
  choices,
  preview,
  onChange,
}: {
  field: FieldSpec;
  value: unknown;
  error: string | undefined;
  choices: Choices;
  preview: PreviewContext;
  onChange: (value: unknown) => void;
}) {
  const { t } = useTranslation();
  const label = t(`workflows.editor.fields.${field.name}`, field.title ?? field.name);
  const hint = field.description;
  const defaultText =
    field.default === undefined || field.default === null
      ? undefined
      : t("workflows.editor.default", { value: JSON.stringify(field.default) });

  switch (field.kind) {
    case "expr":
    case "tpl": {
      const key = field.kind === "expr" ? "$expr" : "$tpl";
      return (
        <ExpressionField
          kind={field.kind}
          label={label}
          value={dynamicText(value, key)}
          workspace={preview.workspace}
          sample={preview.sample}
          required={field.required}
          hint={hint}
          error={error}
          onChange={(text) => onChange(text ? { [key]: text } : undefined)}
        />
      );
    }
    case "const":
      return (
        <p>
          {label} : <code>{JSON.stringify(field.value)}</code>
        </p>
      );
    case "boolean": {
      const checked = typeof value === "boolean" ? value : field.default === true;
      return (
        <div className="vv-field">
          <Checkbox label={label} checked={checked} onChange={(v) => onChange(v)} />
          {error ? <span className="vv-field-error">{error}</span> : null}
        </div>
      );
    }
    case "number":
      return (
        <NumberInput
          label={label}
          value={value}
          min={field.min}
          max={field.max}
          integer={field.integer}
          required={field.required}
          hint={[hint, defaultText].filter(Boolean).join(" · ") || undefined}
          error={error}
          onChange={onChange}
        />
      );
    case "enum":
      return (
        <div className="vv-field-group">
          <SelectField
            label={label}
            value={typeof value === "string" ? value : ""}
            onChange={(v) => onChange(v || undefined)}
            options={[
              {
                value: "",
                label:
                  field.default !== undefined && field.default !== null
                    ? t("workflows.editor.byDefault", { value: String(field.default) })
                    : "—",
              },
              ...field.options.map((o) => ({ value: o, label: o })),
            ]}
          />
          {error ? <span className="vv-field-error">{error}</span> : null}
        </div>
      );
    case "multi": {
      const selected = Array.isArray(value)
        ? value.map(String)
        : Array.isArray(field.default)
          ? field.default.map(String)
          : [];
      return (
        <fieldset className="vv-field">
          <legend>{label}</legend>
          {field.options.map((o) => (
            <Checkbox
              key={o}
              label={t(`workflows.editor.options.${o}`, o)}
              checked={selected.includes(o)}
              onChange={(on) => onChange(on ? [...selected, o] : selected.filter((s) => s !== o))}
            />
          ))}
          {error ? <span className="vv-field-error">{error}</span> : null}
        </fieldset>
      );
    }
    case "list":
      return (
        <TextField
          label={label}
          value={Array.isArray(value) ? value.join(", ") : ""}
          hint={t("workflows.editor.listHint")}
          error={error}
          onChange={(e) => {
            const items = splitList(e.target.value);
            onChange(items.length ? items : undefined);
          }}
        />
      );
    case "reference":
      return (
        <ReferenceField
          label={label}
          field={field}
          value={value}
          error={error}
          choices={choices}
          onChange={onChange}
        />
      );
    case "string":
      return (
        <TextField
          label={label}
          value={typeof value === "string" ? value : ""}
          maxLength={field.maxLength}
          placeholder={typeof field.default === "string" ? field.default : undefined}
          required={field.required}
          hint={hint}
          error={error}
          onChange={(e) => onChange(e.target.value || undefined)}
        />
      );
    case "json":
      return (
        <JsonField label={label} value={value} hint={hint} error={error} onChange={onChange} />
      );
  }
}

function ReferenceField({
  label,
  field,
  value,
  error,
  choices,
  onChange,
}: {
  label: string;
  field: Extract<FieldSpec, { kind: "reference" }>;
  value: unknown;
  error: string | undefined;
  choices: Choices;
  onChange: (value: unknown) => void;
}) {
  const { t } = useTranslation();
  const current = typeof value === "string" ? value : "";
  let options: { value: string; label: string }[] | null = null;
  if (field.ref.kind === "connector" && choices.connectors) {
    options = choices.connectors
      .filter(
        (c) =>
          (!field.ref.family || c.family === field.ref.family) &&
          (field.ref.connector_kinds.length === 0 || field.ref.connector_kinds.includes(c.kind)),
      )
      .map((c) => ({ value: c.id, label: `${c.name} (${c.kind})${c.enabled ? "" : " ⏸"}` }));
  } else if (field.ref.kind === "agent" && choices.agents) {
    options = choices.agents.map((a) => ({
      value: a.id,
      label: a.enabled ? a.name : `${a.name} ⏸`,
    }));
  }
  if (!options) {
    // The list is out of reach (permission): the identifier is typed, the server checks it.
    return (
      <TextField
        label={label}
        className="vv-code"
        value={current}
        hint={field.description}
        error={error}
        onChange={(e) => onChange(e.target.value.trim() || undefined)}
      />
    );
  }
  if (current && !options.some((o) => o.value === current)) {
    options.push({ value: current, label: t("workflows.editor.missingReference") });
  }
  return (
    <div className="vv-field-group">
      <SelectField
        label={label}
        value={current}
        onChange={(v) => onChange(v || undefined)}
        options={[{ value: "", label: "—" }, ...options]}
      />
      {options.length === 0 ? (
        <span className="vv-field-hint">
          {t(`workflows.editor.noReference.${field.ref.kind}`, {
            kinds: field.ref.connector_kinds.join(", "),
          })}
        </span>
      ) : null}
      {error ? <span className="vv-field-error">{error}</span> : null}
    </div>
  );
}

/** Object parameters (field maps, query strings): edited as JSON, applied once valid. */
function JsonField({
  label,
  value,
  hint,
  error,
  onChange,
}: {
  label: string;
  value: unknown;
  hint: string | undefined;
  error: string | undefined;
  onChange: (value: unknown) => void;
}) {
  const { t } = useTranslation();
  const [text, setText] = useState(value === undefined ? "" : JSON.stringify(value, null, 2));
  const [invalid, setInvalid] = useState(false);
  return (
    <TextArea
      label={label}
      className="vv-textarea vv-code"
      value={text}
      rows={4}
      spellCheck={false}
      hint={invalid ? t("workflows.invalidJson") : (error ?? hint)}
      onChange={(e) => {
        setText(e.target.value);
        if (!e.target.value.trim()) {
          setInvalid(false);
          onChange(undefined);
          return;
        }
        try {
          onChange(JSON.parse(e.target.value));
          setInvalid(false);
        } catch {
          setInvalid(true);
        }
      }}
    />
  );
}
