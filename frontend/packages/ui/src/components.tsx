import {
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  useEffect,
  useId,
  useRef,
} from "react";

type Variant = "primary" | "secondary" | "danger";

export function Button({
  variant = "primary",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      {...props}
      className={["vv-button", `vv-button-${variant}`, className].filter(Boolean).join(" ")}
    />
  );
}

export interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  error?: string | undefined;
}

export function TextField({ label, hint, error, id, ...props }: TextFieldProps) {
  const generated = useId();
  const inputId = id ?? generated;
  const hintId = `${inputId}-hint`;
  return (
    <div className="vv-field">
      <label htmlFor={inputId}>{label}</label>
      <input
        id={inputId}
        aria-invalid={error ? true : undefined}
        aria-describedby={hint || error ? hintId : undefined}
        {...props}
      />
      {error ? (
        <span id={hintId} className="vv-field-error">
          {error}
        </span>
      ) : hint ? (
        <span id={hintId} className="vv-field-hint">
          {hint}
        </span>
      ) : null}
    </div>
  );
}

export function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
}) {
  const id = useId();
  return (
    <div className="vv-field">
      <label htmlFor={id}>{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function Alert({
  tone = "error",
  children,
}: {
  tone?: "error" | "info" | "success";
  children: ReactNode;
}) {
  return (
    <div className={`vv-alert vv-alert-${tone}`} role={tone === "error" ? "alert" : "status"}>
      {children}
    </div>
  );
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="vv-card">
      {title ? <h2 className="vv-card-title">{title}</h2> : null}
      {children}
    </section>
  );
}

export function PageHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  return (
    <div className="vv-page-header">
      <h1>{title}</h1>
      {actions ? <div className="vv-page-actions">{actions}</div> : null}
    </div>
  );
}

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "ok" | "warn" | "error";
  children: ReactNode;
}) {
  return <span className={`vv-badge vv-badge-${tone}`}>{children}</span>;
}

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
}

export function DataTable<T>({
  rows,
  columns,
  rowKey,
  empty,
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  empty: string;
}) {
  if (rows.length === 0) return <p className="vv-muted">{empty}</p>;
  return (
    <div className="vv-table-wrap">
      <table className="vv-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)}>
              {columns.map((c) => (
                <td key={c.key}>{c.render(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Native modal dialog (focus trap and Escape handled by the browser). */
export function Dialog({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal?.();
    if (!open && dialog.open) dialog.close?.();
  }, [open]);
  return (
    <dialog ref={ref} className="vv-dialog" onClose={onClose} aria-labelledby="vv-dialog-title">
      <h2 id="vv-dialog-title">{title}</h2>
      {open ? children : null}
    </dialog>
  );
}
