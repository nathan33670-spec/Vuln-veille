import { unwrap } from "@vv/api-client";
import { Alert, Badge, Button, SelectField, TextArea, TextField } from "@vv/ui";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

import { client } from "../../api";
import { apiDetail } from "../ai/shared";
import { type DraftRequest, followDraft } from "./shared";

/** A draft asked of the workspace's AI engine, followed until its bulletin exists. */
export function DraftRequestForm({
  workspace,
  vulnerabilityId,
  vulnerabilityLabel,
  cveId,
}: {
  workspace: string;
  vulnerabilityId?: string | undefined;
  vulnerabilityLabel?: string | undefined;
  cveId?: string | undefined;
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [request, setRequest] = useState<DraftRequest>();
  const [error, setError] = useState<string>();
  const [templateId, setTemplateId] = useState("");
  const [language, setLanguage] = useState("");
  const templates = useQuery({
    queryKey: ["bulletin-templates", workspace],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/bulletin-templates", {
          params: { path: { workspace } },
        }),
      ),
  });

  const requestId = request?.id;
  useEffect(() => {
    if (!requestId) return;
    return followDraft(workspace, requestId, setRequest);
  }, [workspace, requestId]);

  const bulletinId = request?.status === "succeeded" ? request.bulletin_id : null;
  useEffect(() => {
    if (bulletinId) void navigate(`/bulletins/${bulletinId}`);
  }, [bulletinId, navigate]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const lines = (name: string) =>
      String(form.get(name) ?? "")
        .split("\n")
        .map((v) => v.trim())
        .filter(Boolean);
    const cve = String(form.get("cve_id") ?? "").trim();
    setError(undefined);
    try {
      const created = unwrap(
        await client.POST("/api/v1/workspaces/{workspace}/draft-requests", {
          params: { path: { workspace } },
          body: {
            vulnerability_ids: vulnerabilityId ? [vulnerabilityId] : [],
            cve_id: !vulnerabilityId && cve ? cve : null,
            urls: lines("urls"),
            text: String(form.get("text") ?? ""),
            template_id: templateId || null,
            language: language || null,
            extra_instructions: String(form.get("extra_instructions") ?? ""),
          },
        }),
      );
      setRequest(created);
    } catch (err) {
      setError(apiDetail(t, err));
    }
  }

  if (request) {
    return (
      <div className="vv-form">
        <p>
          {t("bulletins.draft.template")} : <strong>{request.template_name ?? "—"}</strong>
          {request.template_version_no ? ` (v${request.template_version_no})` : ""}
        </p>
        {request.selection_reasons.length ? (
          <p className="vv-muted">
            {t("bulletins.draft.reasons")} : {request.selection_reasons.join(" ; ")}
          </p>
        ) : null}
        <ol aria-label={t("bulletins.draft.progress")}>
          {request.progress.map((step, index) => {
            const name = String((step as { step?: unknown }).step ?? "");
            return <li key={`${name}-${index}`}>{t(`bulletins.draft.step.${name}`, name)}</li>;
          })}
        </ol>
        {request.status === "failed" ? (
          <Alert>
            {t("bulletins.draft.failed")} :{" "}
            {t(`bulletins.draft.error.${request.error ?? "internal_error"}`, request.error ?? "")}
          </Alert>
        ) : (
          <p role="status">
            <Badge tone="warn">{t(`bulletins.draft.status.${request.status}`)}</Badge>
          </p>
        )}
        {request.status === "failed" ? (
          <Button variant="secondary" onClick={() => setRequest(undefined)}>
            {t("bulletins.draft.retry")}
          </Button>
        ) : null}
      </div>
    );
  }

  const active = (templates.data ?? []).filter((tpl) => tpl.status === "active");
  return (
    <form onSubmit={submit} className="vv-form">
      {vulnerabilityId ? (
        <p>
          {t("bulletins.draft.vulnerability")} :{" "}
          <strong>{vulnerabilityLabel ?? vulnerabilityId}</strong>
        </p>
      ) : (
        <TextField
          name="cve_id"
          label={t("bulletins.draft.cve")}
          defaultValue={cveId ?? ""}
          placeholder="CVE-2026-12345"
          pattern="CVE-\d{4}-\d{4,}"
        />
      )}
      <TextArea
        name="urls"
        label={t("bulletins.draft.urls")}
        hint={t("bulletins.draft.urlsHint")}
        rows={3}
      />
      <TextArea name="text" label={t("bulletins.draft.text")} rows={4} maxLength={20000} />
      <SelectField
        label={t("bulletins.draft.template")}
        value={templateId}
        onChange={setTemplateId}
        options={[
          { value: "", label: t("bulletins.draft.auto") },
          ...active.map((tpl) => ({
            value: tpl.id,
            label: `${tpl.name}${tpl.language ? ` (${tpl.language.toUpperCase()})` : ""}`,
          })),
        ]}
      />
      <SelectField
        label={t("bulletins.draft.language")}
        value={language}
        onChange={setLanguage}
        options={[
          { value: "", label: t("bulletins.draft.auto") },
          { value: "fr", label: t("bulletins.language.fr") },
          { value: "en", label: t("bulletins.language.en") },
        ]}
      />
      <TextArea
        name="extra_instructions"
        label={t("bulletins.draft.instructions")}
        rows={2}
        maxLength={2000}
      />
      {error ? <Alert>{error}</Alert> : null}
      <p className="vv-muted">{t("bulletins.draft.aiNotice")}</p>
      <Button type="submit">{t("bulletins.draft.submit")}</Button>
    </form>
  );
}
