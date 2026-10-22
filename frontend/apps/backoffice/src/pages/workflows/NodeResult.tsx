import type { Schemas } from "@vv/api-client";
import { Alert } from "@vv/ui";
import { useTranslation } from "react-i18next";

import { duration, JsonBlock, StatusBadge } from "./shared";

type NodeRunDetail = Schemas["NodeRunDetailOut"];

/** A node's output, logs and costs: collected or generated data, shown as text. */
export function NodeResult({
  result,
  runId,
}: {
  result: NodeRunDetail;
  runId?: string | undefined;
}) {
  const { t } = useTranslation();
  return (
    <div className="vv-test-result">
      <dl className="vv-kv">
        <dt>{t("workflows.state")}</dt>
        <dd>
          <StatusBadge status={result.status} />
        </dd>
        <dt>{t("workflows.duration")}</dt>
        <dd>{duration(result.started_at, result.finished_at)}</dd>
        <dt>{t("runs.itemsIn")}</dt>
        <dd>{result.input_count}</dd>
        <dt>{t("runs.itemsOut")}</dt>
        <dd>
          {result.output_count}
          {result.output_truncated ? ` (${t("runs.truncated")})` : ""}
        </dd>
        {result.ai_calls ? (
          <>
            <dt>{t("workflows.editor.test.aiCost")}</dt>
            <dd>
              {t("workflows.editor.test.aiCalls", {
                count: result.ai_calls,
                cost: Number(result.ai_cost_usd ?? 0).toFixed(4),
              })}
            </dd>
          </>
        ) : null}
        {runId ? (
          <>
            <dt>{t("workflows.editor.test.runId")}</dt>
            <dd>
              <code>{runId}</code>
            </dd>
          </>
        ) : null}
      </dl>
      {result.error ? <Alert>{result.error}</Alert> : null}
      <p className="vv-muted">{t("runs.untrustedHint")}</p>
      {Object.entries(result.output).map(([port, items]) => (
        <details key={port} open>
          <summary>
            {t("workflows.editor.test.port", {
              port,
              count: Array.isArray(items) ? items.length : 0,
            })}
          </summary>
          <JsonBlock value={items} />
        </details>
      ))}
      {result.logs.length ? (
        <details>
          <summary>{t("runs.logs")}</summary>
          <JsonBlock value={result.logs} />
        </details>
      ) : null}
    </div>
  );
}
