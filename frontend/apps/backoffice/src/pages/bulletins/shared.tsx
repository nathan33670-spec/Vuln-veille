import { type Schemas, unwrap } from "@vv/api-client";
import { Badge } from "@vv/ui";
import { useTranslation } from "react-i18next";

import { client } from "../../api";

export type Bulletin = Schemas["BulletinOut"];
export type BulletinDetail = Schemas["BulletinDetailOut"];
export type DraftRequest = Schemas["DraftRequestOut"];

export const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] as const;
export const LANGUAGES = ["fr", "en"] as const;

const STATUS_TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  draft: "neutral",
  in_review: "warn",
  approved: "ok",
  published: "ok",
  withdrawn: "error",
};

export function BulletinStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <Badge tone={STATUS_TONE[status] ?? "neutral"}>{t(`bulletins.status.${status}`, status)}</Badge>
  );
}

const TLP_TONE: Record<string, "neutral" | "ok" | "warn" | "error"> = {
  CLEAR: "neutral",
  GREEN: "ok",
  AMBER: "warn",
  "AMBER+STRICT": "warn",
  RED: "error",
};

export function TlpBadge({ tlp }: { tlp: string }) {
  return <Badge tone={TLP_TONE[tlp] ?? "neutral"}>TLP:{tlp}</Badge>;
}

export function BulletinSeverity({ severity }: { severity: string | null | undefined }) {
  const { t } = useTranslation();
  if (!severity) return <Badge>—</Badge>;
  const tone = severity === "critical" || severity === "high" ? "error" : "warn";
  return (
    <Badge tone={severity === "low" ? "ok" : tone}>{t(`bulletins.severity.${severity}`)}</Badge>
  );
}

// --- Template fields (spec 04 §1) -------------------------------------------------

export interface TemplateField {
  key: string;
  label?: string;
  type: string;
  required?: boolean;
  max_length?: number | null;
  options?: string[];
  item_schema?: Record<string, string> | null;
  generation?: { mode?: string; instructions?: string; from?: string };
}

export function templateFields(spec: Record<string, unknown> | null | undefined): TemplateField[] {
  const fields = spec?.fields;
  return Array.isArray(fields) ? (fields as TemplateField[]) : [];
}

/** Fields edited as JSON in the bulletin editor (objects and lists of objects). */
export function isJsonField(field: TemplateField): boolean {
  return (
    field.type === "cvss" ||
    field.type === "products" ||
    field.type === "references" ||
    (field.type === "list" && Boolean(field.item_schema))
  );
}

/** A field value as the editor shows it (always text, except booleans). */
export function toEditor(field: TemplateField, value: unknown): string | boolean {
  if (field.type === "boolean") return Boolean(value);
  if (value === null || value === undefined) return isJsonField(field) ? "" : "";
  if (isJsonField(field)) return JSON.stringify(value, null, 2);
  if (field.type === "list") return Array.isArray(value) ? value.join("\n") : "";
  return String(value);
}

/** Back from the editor; `undefined` when a JSON field does not parse. */
export function fromEditor(field: TemplateField, value: string | boolean): unknown {
  if (field.type === "boolean") return Boolean(value);
  const text = String(value);
  if (isJsonField(field)) {
    if (!text.trim()) return field.type === "cvss" ? null : [];
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return undefined;
    }
  }
  if (field.type === "list")
    return text
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
  if (!text && !field.required && (field.type === "enum" || field.type === "date")) return null;
  return text;
}

// --- Draft requests ---------------------------------------------------------------

export const DRAFT_TERMINAL = new Set(["succeeded", "failed"]);
const POLL_MS = 1500;

async function fetchDraft(workspace: string, id: string): Promise<DraftRequest> {
  return unwrap(
    await client.GET("/api/v1/workspaces/{workspace}/draft-requests/{request_id}", {
      params: { path: { workspace, request_id: id } },
    }),
  );
}

/**
 * Follows a draft request until it ends: its server-sent events, or polling where
 * EventSource is missing or the stream breaks. Returns the function that stops it.
 */
export function followDraft(
  workspace: string,
  id: string,
  onUpdate: (request: DraftRequest) => void,
): () => void {
  if (typeof EventSource === "undefined") return poll(workspace, id, onUpdate);
  const source = new EventSource(
    `/api/v1/workspaces/${encodeURIComponent(workspace)}/draft-requests/${encodeURIComponent(id)}/events`,
  );
  let fallback: (() => void) | null = null;
  source.addEventListener("progress", (event) => {
    onUpdate(JSON.parse((event as MessageEvent<string>).data) as DraftRequest);
  });
  source.addEventListener("done", () => {
    source.close();
    fallback ??= poll(workspace, id, onUpdate); // the final state, with its bulletin
  });
  source.onerror = () => {
    source.close();
    fallback ??= poll(workspace, id, onUpdate);
  };
  return () => {
    source.close();
    fallback?.();
  };
}

function poll(
  workspace: string,
  id: string,
  onUpdate: (request: DraftRequest) => void,
): () => void {
  let stopped = false;
  let timer: number | undefined;
  const tick = async () => {
    try {
      const request = await fetchDraft(workspace, id);
      if (stopped) return;
      onUpdate(request);
      if (DRAFT_TERMINAL.has(request.status)) return;
    } catch {
      // transient: the next tick retries
    }
    if (!stopped) timer = window.setTimeout(tick, POLL_MS);
  };
  void tick();
  return () => {
    stopped = true;
    window.clearTimeout(timer);
  };
}
