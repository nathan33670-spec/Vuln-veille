import { TextField } from "@vv/ui";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { CATEGORIES, type NodeType } from "./model";

export const DRAG_TYPE = "application/x-vv-node-type";

/** Node types from the backend registry, by category; drag one onto the canvas or click it. */
export function Palette({
  types,
  can,
  onAdd,
}: {
  types: NodeType[];
  can: (permission: string) => boolean;
  onAdd: (type: string) => void;
}) {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const needle = search.trim().toLowerCase();
  const shown = types.filter(
    (nt) =>
      !needle || nt.label.toLowerCase().includes(needle) || nt.type.toLowerCase().includes(needle),
  );
  const categories = [
    ...CATEGORIES.filter((c) => shown.some((nt) => nt.category === c)),
    ...new Set(
      shown.map((nt) => nt.category).filter((c) => !(CATEGORIES as readonly string[]).includes(c)),
    ),
  ];
  return (
    <nav className="vv-editor-palette" aria-label={t("workflows.editor.palette")}>
      <TextField
        label={t("workflows.editor.search")}
        type="search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      {categories.map((category) => (
        <section key={category}>
          <h3 className="vv-editor-palette-title">
            {t(`workflows.editor.categories.${category}`, category)}
          </h3>
          <ul>
            {shown
              .filter((nt) => nt.category === category)
              .map((nt) => {
                const missing = nt.required_permissions.filter((p) => !can(p));
                return (
                  <li key={nt.type}>
                    <button
                      type="button"
                      className="vv-editor-palette-item"
                      draggable={missing.length === 0}
                      disabled={missing.length > 0}
                      title={
                        missing.length
                          ? t("workflows.editor.missingPermission", {
                              permissions: missing.join(", "),
                            })
                          : nt.type
                      }
                      onDragStart={(e) => {
                        e.dataTransfer.setData(DRAG_TYPE, nt.type);
                        e.dataTransfer.effectAllowed = "move";
                      }}
                      onClick={() => onAdd(nt.type)}
                    >
                      {nt.label}
                    </button>
                  </li>
                );
              })}
          </ul>
        </section>
      ))}
      {categories.length === 0 ? <p className="vv-muted">{t("workflows.editor.noMatch")}</p> : null}
    </nav>
  );
}
