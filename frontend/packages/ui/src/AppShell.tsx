import type { ReactNode } from "react";

export interface AppShellProps {
  title: string;
  subtitle?: string;
  /** Shown before the title (an issuer's logo…). */
  brand?: ReactNode;
  nav?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

export function AppShell({ title, subtitle, brand, nav, actions, children }: AppShellProps) {
  return (
    <div className="vv-shell">
      <header className="vv-header">
        {brand}
        <span className="vv-brand">{title}</span>
        {subtitle ? <span className="vv-subtitle">{subtitle}</span> : null}
        {nav ? <nav className="vv-nav">{nav}</nav> : null}
        {actions ? <div className="vv-header-actions">{actions}</div> : null}
      </header>
      <main className="vv-main">{children}</main>
    </div>
  );
}
