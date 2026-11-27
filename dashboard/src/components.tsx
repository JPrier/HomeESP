import type { ReactNode } from "react";
import { ICON, tone, UNKNOWN } from "./lib/format";

/** State badge: colour + icon + text, so meaning never depends on colour alone. */
export function Badge({ state }: { state: string | null | undefined }) {
  const t = tone(state);
  const label = state ?? UNKNOWN;
  return (
    <span className={`badge tone-${t}`} role="status" aria-label={label}>
      <span aria-hidden="true">{ICON[t]}</span> {label}
    </span>
  );
}

export function Card({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card" aria-label={title}>
      <header>
        <h2>{title}</h2>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className={`stat ${value === UNKNOWN ? "is-unknown" : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  return error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}
