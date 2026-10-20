import type { ReactNode } from "react";

export interface AppShellProps {
  title: string;
  subtitle?: string;
  nav?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

export function AppShell({ title, subtitle, nav, actions, children }: AppShellProps) {
  return (
    <div className="vv-shell">
      <header className="vv-header">
        <span className="vv-brand">{title}</span>
        {subtitle ? <span className="vv-subtitle">{subtitle}</span> : null}
        {nav ? <nav className="vv-nav">{nav}</nav> : null}
        {actions ? <div className="vv-header-actions">{actions}</div> : null}
      </header>
      <main className="vv-main">{children}</main>
    </div>
  );
}
