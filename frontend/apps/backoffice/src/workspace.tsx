import { useMe } from "@vv/auth";
import { SelectField } from "@vv/ui";
import { createContext, type ReactNode, useContext, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

const STORAGE_KEY = "vv.workspace";

interface WorkspaceContextValue {
  /** Slug of the team the user works for right now (VOC or CERT). */
  slug: string | null;
  setSlug: (slug: string) => void;
  /** Permissions of the user in that workspace. */
  can: (permission: string) => boolean;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

function remembered(): string | null {
  try {
    return globalThis.localStorage?.getItem(STORAGE_KEY) ?? null;
  } catch {
    return null; // storage disabled: fall back to the first workspace
  }
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const me = useMe().data;
  const [chosen, setChosen] = useState<string | null>(remembered);
  const workspaces = me?.workspaces ?? [];
  const current = workspaces.find((w) => w.slug === chosen) ?? workspaces[0] ?? null;
  const value = useMemo<WorkspaceContextValue>(
    () => ({
      slug: current?.slug ?? null,
      setSlug: (slug: string) => {
        setChosen(slug);
        try {
          globalThis.localStorage?.setItem(STORAGE_KEY, slug);
        } catch {
          // a preference only
        }
      },
      can: (permission: string) => Boolean(current?.permissions.includes(permission)),
    }),
    [current],
  );
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("WorkspaceProvider missing");
  return value;
}

export function WorkspaceSwitcher() {
  const { t } = useTranslation();
  const me = useMe().data;
  const { slug, setSlug } = useWorkspace();
  const workspaces = me?.workspaces ?? [];
  if (workspaces.length < 2 || !slug) return null;
  return (
    <SelectField
      label={t("workspace.current")}
      value={slug}
      onChange={setSlug}
      options={workspaces.map((w) => ({ value: w.slug, label: w.name }))}
    />
  );
}
