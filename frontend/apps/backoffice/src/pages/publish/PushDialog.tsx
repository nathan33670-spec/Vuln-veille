import { type Schemas, unwrap } from "@vv/api-client";
import { useStepUp } from "@vv/auth";
import { Alert, Button, Dialog, SelectField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { apiDetail } from "../ai/shared";
import { PushStatusBadge, usePush } from "./shared";

/** « Pousser vers… » : choose a target, read the exact request (credentials masked),
 * confirm (second factor at the first push to that target), then follow the push. */
export function PushDialog({
  workspace,
  bulletinId,
  open,
  onClose,
}: {
  workspace: string;
  bulletinId: string;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const withStepUp = useStepUp();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [request, setRequest] = useState<Schemas["PreparedOut"]>();
  const [error, setError] = useState<string>();
  const [pushId, setPushId] = useState<string>();
  const push = usePush(workspace, pushId);
  const targets = useQuery({
    queryKey: ["publish-targets", workspace],
    enabled: open,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/publish-targets", {
          params: { path: { workspace } },
        }),
      ),
  });
  const usable = (targets.data ?? []).filter((c) => c.enabled);

  useEffect(() => {
    if (!target) return;
    let cancelled = false;
    void (async () => {
      try {
        const shown = unwrap(
          await client.POST(
            "/api/v1/workspaces/{workspace}/publish-targets/{connector_id}/dry-run",
            {
              params: { path: { workspace, connector_id: target } },
              body: { bulletin_id: bulletinId },
            },
          ),
        );
        if (!cancelled) {
          setRequest(shown);
          setError(undefined);
        }
      } catch (err) {
        if (!cancelled) {
          setRequest(undefined);
          setError(apiDetail(t, err));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [workspace, target, bulletinId, t]);

  useEffect(() => {
    if (push && (push.status === "succeeded" || push.status === "failed"))
      void queryClient.invalidateQueries({ queryKey: ["publications", workspace] });
  }, [push, queryClient, workspace]);

  async function confirm() {
    try {
      const queued = await withStepUp(async () =>
        unwrap(
          await client.POST("/api/v1/workspaces/{workspace}/bulletins/{bulletin_id}/push", {
            params: { path: { workspace, bulletin_id: bulletinId } },
            body: { connector_id: target },
          }),
        ),
      );
      setPushId(queued.id);
    } catch (err) {
      setError(apiDetail(t, err));
    }
  }

  function close() {
    setTarget("");
    setRequest(undefined);
    setError(undefined);
    setPushId(undefined);
    onClose();
  }

  return (
    <Dialog open={open} title={t("publish.push.title")} onClose={close}>
      <div className="vv-form">
        {pushId ? (
          push ? (
            <div role="status">
              <p>
                <PushStatusBadge status={push.status} />{" "}
                {push.response_status ? `HTTP ${push.response_status}` : ""}{" "}
                {push.remote_id ? t("publish.journal.remote", { id: push.remote_id }) : ""}
              </p>
              {push.error ? <Alert>{push.error}</Alert> : null}
              {push.status === "retrying" ? (
                <p className="vv-muted">{t("publish.push.retrying")}</p>
              ) : null}
            </div>
          ) : (
            <p role="status">{t("publish.push.queued")}</p>
          )
        ) : (
          <>
            <SelectField
              label={t("publish.push.target")}
              value={target}
              onChange={setTarget}
              options={[
                { value: "", label: "—" },
                ...usable.map((c) => ({
                  value: c.id,
                  label: `${c.name}${c.scope === "global" ? ` (${t("publish.list.scopes.global")})` : ""}`,
                })),
              ]}
            />
            {usable.length === 0 && targets.isSuccess ? (
              <p className="vv-muted">{t("publish.push.noTarget")}</p>
            ) : null}
            {error ? <Alert>{error}</Alert> : null}
            {request ? (
              <>
                <p className="vv-muted">{t("publish.push.dryRun")}</p>
                <pre className="vv-pre" aria-label={t("publish.preview.request")}>
                  {`${request.method} ${request.url}\n${Object.entries(request.headers)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("\n")}\n\n${request.body}`}
                </pre>
                <Button onClick={() => void confirm()}>{t("publish.push.confirm")}</Button>
              </>
            ) : null}
          </>
        )}
        <Button variant="secondary" onClick={close}>
          {pushId ? t("publish.push.close") : t("common.cancel")}
        </Button>
      </div>
    </Dialog>
  );
}
