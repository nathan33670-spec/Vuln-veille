export const WORKFLOW_FORMAT = "vuln-veille.workflow/1";
const MAX_FILE_BYTES = 1024 * 1024;

export interface WorkflowFile {
  name: string;
  description: string;
  tags: string[];
  graph: Record<string, unknown>;
}

export class WorkflowFileError extends Error {}

/**
 * A workflow file chosen by the analyst: the export format, or a bare graph. It is parsed
 * as JSON only; the server validates the graph like any other before it is stored.
 */
export async function readWorkflowFile(file: File): Promise<WorkflowFile> {
  if (file.size > MAX_FILE_BYTES) throw new WorkflowFileError("too_large");
  let data: unknown;
  try {
    data = JSON.parse(await file.text());
  } catch {
    throw new WorkflowFileError("invalid_json");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new WorkflowFileError("not_a_workflow");
  }
  const record = data as Record<string, unknown>;
  const graph = record.format === WORKFLOW_FORMAT ? record.graph : record;
  if (!graph || typeof graph !== "object" || !Array.isArray((graph as { nodes?: unknown }).nodes)) {
    throw new WorkflowFileError("not_a_workflow");
  }
  const fallback = file.name.replace(/\.json$/i, "").slice(0, 120) || "Workflow";
  return {
    name: typeof record.name === "string" && record.name ? record.name.slice(0, 120) : fallback,
    description: typeof record.description === "string" ? record.description.slice(0, 2000) : "",
    tags: Array.isArray(record.tags)
      ? record.tags.filter((x): x is string => typeof x === "string").slice(0, 20)
      : [],
    graph: graph as Record<string, unknown>,
  };
}
