import type { ReactNode } from "react";

export interface AppShellProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

export function AppShell({ title, subtitle, children }: AppShellProps) {
  return (
    <div className="vv-shell">
      <header className="vv-header">
        <span className="vv-brand">{title}</span>
        {subtitle ? <span className="vv-subtitle">{subtitle}</span> : null}
      </header>
      <main className="vv-main">{children}</main>
    </div>
  );
}
