import { type Schemas, unwrap } from "@vv/api-client";

import { client } from "../../api";
import { TERMINAL } from "./shared";

export type NodeRun = Schemas["NodeRunOut"];

export interface RunListener {
  onNode: (node: NodeRun) => void;
  onRun: (status: string, error: string | null) => void;
}

const POLL_MS = 1500;

/**
 * Follows a run as it progresses: the server-sent events stream (`/runs/{id}/events`),
 * or polling where EventSource is missing. Returns the function that stops following.
 * Event payloads are data from the API, parsed as JSON and never interpreted further.
 */
export function followRun(workspace: string, runId: string, listener: RunListener): () => void {
  if (typeof EventSource === "undefined") return poll(workspace, runId, listener);
  const source = new EventSource(
    `/api/v1/workspaces/${encodeURIComponent(workspace)}/runs/${encodeURIComponent(runId)}/events`,
  );
  source.addEventListener("node", (event) => {
    listener.onNode(JSON.parse((event as MessageEvent<string>).data) as NodeRun);
  });
  source.addEventListener("run", (event) => {
    const data = JSON.parse((event as MessageEvent<string>).data) as {
      status: string;
      error: string | null;
    };
    listener.onRun(data.status, data.error);
    if (TERMINAL.has(data.status)) source.close();
  });
  // The stream ends after ten minutes or on a network error: polling takes over.
  let fallback: (() => void) | null = null;
  source.onerror = () => {
    source.close();
    fallback ??= poll(workspace, runId, listener);
  };
  return () => {
    source.close();
    fallback?.();
  };
}

function poll(workspace: string, runId: string, listener: RunListener): () => void {
  let stopped = false;
  let timer: number | undefined;
  const tick = async () => {
    try {
      const run = unwrap(
        await client.GET("/api/v1/workspaces/{workspace}/runs/{run_id}", {
          params: { path: { workspace, run_id: runId } },
        }),
      );
      if (stopped) return;
      run.node_runs.forEach(listener.onNode);
      listener.onRun(run.status, run.error);
      if (TERMINAL.has(run.status)) return;
    } catch {
      // A transient failure: the next tick retries.
    }
    if (!stopped) timer = window.setTimeout(tick, POLL_MS);
  };
  void tick();
  return () => {
    stopped = true;
    window.clearTimeout(timer);
  };
}
