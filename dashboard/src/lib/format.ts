// Formatting helpers. The rule everywhere: missing data is shown as unknown, never 0.

export const UNKNOWN = "unknown";

export function ms(v: number | null | undefined, digits = 1): string {
  return v === null || v === undefined || !Number.isFinite(v) ? UNKNOWN : `${v.toFixed(digits)} ms`;
}

export function pct(v: number | null | undefined, digits = 1): string {
  return v === null || v === undefined || !Number.isFinite(v) ? UNKNOWN : `${v.toFixed(digits)} %`;
}

export function dbm(v: number | null | undefined): string {
  return v === null || v === undefined ? UNKNOWN : `${v} dBm`;
}

/** Relative age from a Unix-ms or ISO timestamp. */
export function age(t: number | string | null | undefined, now = Date.now()): string {
  if (t === null || t === undefined) return "never";
  const ts = typeof t === "number" ? t : Date.parse(t);
  if (!Number.isFinite(ts)) return UNKNOWN;
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function utc(t: number | string | null | undefined): string {
  if (t === null || t === undefined) return UNKNOWN;
  const d = new Date(typeof t === "number" ? t : Date.parse(t));
  return Number.isNaN(d.getTime()) ? UNKNOWN : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export type Tone = "good" | "warn" | "bad" | "unknown" | "muted";

/** Map any state vocabulary to a tone (colour + icon + text are always shown together). */
export function tone(state: string | null | undefined): Tone {
  switch (state) {
    case "healthy":
    case "online":
    case "located":
    case "resolved":
    case "sent":
      return "good";
    case "degraded":
    case "stale":
    case "recovering":
    case "ambiguous":
    case "warning":
    case "pending":
      return "warn";
    case "failed":
    case "missing":
    case "open":
    case "critical":
      return "bad";
    case "maintenance":
    case "disabled":
    case "suppressed":
      return "muted";
    default:
      return "unknown";
  }
}

export const ICON: Record<Tone, string> = { good: "●", warn: "▲", bad: "✖", unknown: "?", muted: "◌" };
