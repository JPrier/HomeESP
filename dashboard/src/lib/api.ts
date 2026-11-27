// API client. The bearer token lives in sessionStorage only (cleared with the tab)
// and is sent as a header; no cookies are used, so there is no CSRF surface.

const KEY = "ho.token";

export function getToken(): string | null {
  return sessionStorage.getItem(KEY);
}

export function setToken(t: string | null): void {
  if (t) sessionStorage.setItem(KEY, t);
  else sessionStorage.removeItem(KEY);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body) headers.set("Content-Type", "application/json");
  const r = await fetch(path, { ...init, headers });
  if (!r.ok) {
    let code = "http_error";
    let message = r.statusText;
    try {
      const b = (await r.json()) as { code?: string; message?: string };
      code = b.code ?? code;
      message = b.message ?? message;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(r.status, code, message);
  }
  const ct = r.headers.get("content-type") ?? "";
  return (ct.includes("json") ? await r.json() : await r.text()) as T;
}

/** Server-sent events over fetch (so the Authorization header can be sent). */
export async function streamEvents(onEvent: (event: string, data: string) => void, signal: AbortSignal): Promise<void> {
  const token = getToken();
  const r = await fetch("/api/v1/events/stream", { headers: token ? { Authorization: `Bearer ${token}` } : {}, signal });
  if (!r.ok || !r.body) throw new ApiError(r.status, "stream", "event stream unavailable");
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    // Bound the buffer: a misbehaving server cannot make the tab grow without limit.
    if (buf.length > 1_000_000) buf = buf.slice(-100_000);
    let idx: number;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let ev = "message";
      const data: string[] = [];
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) ev = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      onEvent(ev, data.join("\n"));
    }
  }
}
