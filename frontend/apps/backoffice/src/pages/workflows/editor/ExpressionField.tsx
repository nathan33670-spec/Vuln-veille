import { unwrap } from "@vv/api-client";
import { errorMessage } from "@vv/auth";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../../api";
import { CodeField } from "./CodeField";

export interface Item {
  json: Record<string, unknown>;
  meta?: Record<string, unknown>;
}

const JMESPATH_FUNCTIONS = [
  "abs",
  "avg",
  "ceil",
  "contains",
  "ends_with",
  "floor",
  "join",
  "keys",
  "length",
  "map",
  "max",
  "max_by",
  "merge",
  "min",
  "min_by",
  "not_null",
  "reverse",
  "sort",
  "sort_by",
  "starts_with",
  "sum",
  "to_array",
  "to_number",
  "to_string",
  "type",
  "values",
];

const LIQUID_WORDS = [
  "if",
  "elsif",
  "else",
  "endif",
  "for",
  "endfor",
  "unless",
  "endunless",
  "capitalize",
  "default",
  "downcase",
  "escape",
  "join",
  "size",
  "strip",
  "truncate",
  "upcase",
];

const PREVIEW_MS = 500;

/** Paths of a sample item (json.cve_id, json.cvss.score…), for autocompletion. */
export function itemPaths(item: Item | undefined, limit = 200): string[] {
  const paths: string[] = ["json", "meta", "run.trigger", "run.payload", "nodes"];
  const walk = (value: unknown, path: string, depth: number) => {
    if (paths.length >= limit || depth > 4) return;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (!/^[A-Za-z_][\w]*$/.test(key)) continue;
        const next = `${path}.${key}`;
        paths.push(next);
        walk(child, next, depth + 1);
      }
    }
  };
  if (item) {
    walk(item.json, "json", 0);
    walk(item.meta ?? {}, "meta", 0);
  }
  return [...new Set(paths)];
}

/**
 * A JMESPath expression or a Liquid template, previewed on the node's sample item by the
 * server's own evaluator (same functions, same limits as when the workflow runs).
 */
export function ExpressionField({
  kind,
  label,
  value,
  onChange,
  workspace,
  sample,
  required,
  hint,
  error,
}: {
  kind: "expr" | "tpl";
  label: string;
  value: string;
  onChange: (value: string) => void;
  workspace: string;
  sample: Item | undefined;
  required?: boolean;
  hint?: string | undefined;
  error?: string | undefined;
}) {
  const { t } = useTranslation();
  const [preview, setPreview] = useState<{ ok: boolean; text: string }>();
  const words = kind === "expr" ? JMESPATH_FUNCTIONS : LIQUID_WORDS;
  const completions = [...itemPaths(sample), ...words];

  useEffect(() => {
    if (!sample || !value) return;
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const result = unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/workflows/preview-expression", {
            params: { path: { workspace } },
            body: {
              ...(kind === "expr" ? { expr: value } : { tpl: value }),
              item: { ...sample },
            },
          }),
        );
        if (cancelled) return;
        if (result.error) setPreview({ ok: false, text: result.error });
        else if (result.truncated) setPreview({ ok: true, text: t("workflows.editor.tooLarge") });
        else setPreview({ ok: true, text: JSON.stringify(result.value, null, 2) ?? "null" });
      } catch (err) {
        if (!cancelled) setPreview({ ok: false, text: errorMessage(t, err) });
      }
    }, PREVIEW_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [kind, value, sample, workspace, t]);

  const suffix = kind === "expr" ? "JMESPath" : "Liquid";
  return (
    <div className="vv-field-group">
      <CodeField
        label={`${label} (${suffix})${required ? " *" : ""}`}
        value={value}
        onChange={onChange}
        completions={completions}
        multiline={kind === "tpl"}
        placeholder={kind === "expr" ? "json.base_score >= `7`" : "{{ json.cve_id }}"}
        hint={hint}
        error={error}
      />
      {!sample ? (
        <span className="vv-field-hint">{t("workflows.editor.previewNeedsSample")}</span>
      ) : value && preview ? (
        <div className="vv-preview" aria-live="polite">
          <span className="vv-muted">{t("workflows.editor.preview")}</span>
          {/* Evaluated on collected data: shown as text only. */}
          <pre className={preview.ok ? "vv-pre vv-untrusted" : "vv-pre vv-field-error"}>
            {preview.text}
          </pre>
        </div>
      ) : null}
    </div>
  );
}
