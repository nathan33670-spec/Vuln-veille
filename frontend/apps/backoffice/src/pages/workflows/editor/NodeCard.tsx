import { Handle, type Node, type NodeProps, Position } from "@xyflow/react";
import { memo } from "react";
import { useTranslation } from "react-i18next";

import type { GraphNode, NodeType } from "./model";

export interface NodeData extends Record<string, unknown> {
  node: GraphNode;
  type: NodeType | undefined;
  errorCount: number;
  /** Run status of the node (run view, node test), when shown. */
  status?: string;
}

export type EditorNode = Node<NodeData, "vv">;

function offset(index: number, count: number): string {
  return `${((index + 1) / (count + 1)) * 100}%`;
}

/** A node on the canvas: its ports are handles, its texts are inert. */
export const NodeCard = memo(function NodeCard({ data, selected }: NodeProps<EditorNode>) {
  const { t } = useTranslation();
  const { node, type, errorCount, status } = data;
  const inputs = type?.inputs ?? [];
  const outputs = type?.outputs ?? [];
  const classes = [
    "vv-flow-node",
    `vv-flow-node-${type?.category ?? "unknown"}`,
    selected ? "vv-flow-node-selected" : "",
    errorCount || !type ? "vv-flow-node-invalid" : "",
    status ? `vv-flow-node-status-${status}` : "",
  ];
  return (
    <div className={classes.filter(Boolean).join(" ")} data-testid={`node-${node.id}`}>
      {inputs.map((port, i) => (
        <Handle
          key={port}
          id={port}
          type="target"
          position={Position.Left}
          style={{ top: offset(i, inputs.length) }}
          aria-label={t("workflows.editor.inputPort", { port })}
        />
      ))}
      <div className="vv-flow-node-category">
        {t(`workflows.editor.categories.${type?.category ?? "unknown"}`)}
      </div>
      <div className="vv-flow-node-title">{node.name || type?.label || node.type}</div>
      <code className="vv-flow-node-id">{node.id}</code>
      {errorCount ? (
        <div className="vv-flow-node-errors">
          {t("workflows.editor.errorCount", { count: errorCount })}
        </div>
      ) : null}
      {status ? (
        <div className="vv-flow-node-status">{t(`workflows.status.${status}`, status)}</div>
      ) : null}
      {outputs.map((port, i) => (
        <Handle
          key={port}
          id={port}
          type="source"
          position={Position.Right}
          style={{ top: offset(i, outputs.length) }}
          aria-label={t("workflows.editor.outputPort", { port })}
        >
          {outputs.length > 1 ? <span className="vv-flow-port-label">{port}</span> : null}
        </Handle>
      ))}
    </div>
  );
});
