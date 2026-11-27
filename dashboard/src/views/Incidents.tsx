import { useState } from "react";
import { Badge, Card, Empty, ErrorNote } from "../components";
import { api } from "../lib/api";
import { age, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { Incident } from "../types";

export function Incidents() {
  const [status, setStatus] = useState("");
  const { data, error } = useApi<{ incidents: Incident[] }>(`/api/v1/incidents${status ? `?status=${status}` : ""}`, 10000);
  return (
    <Card
      title="Incidents"
      actions={
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">all</option>
          <option>open</option>
          <option>recovering</option>
          <option>resolved</option>
        </select>
      }
    >
      <ErrorNote error={error} />
      {data && data.incidents.length === 0 && <Empty>No incidents recorded.</Empty>}
      <ul className="list">
        {data?.incidents.map((i) => (
          <li key={i.id}>
            <Badge state={i.status} /> <Badge state={i.severity} /> <a href={`#/incidents/${i.id}`}>{i.id}</a> — {i.hypothesis.title}
            <div className="muted">
              opened {utc(i.opened_at)} ({age(i.opened_at)}) · episode {i.episode}
              {i.flaps > 0 ? ` · flapped ${i.flaps}×` : ""} {i.acknowledged ? " · acknowledged" : ""}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

interface Timeline {
  kind: string;
  episode: number;
  severity: string;
  at: number;
  title: string;
  summary: string;
}

export function IncidentDetail({ id }: { id: string }) {
  const { data, error, reload } = useApi<{ incident: Incident & { notes: Array<{ at: number; actor: string; note: string }> }; timeline: Timeline[] }>(
    `/api/v1/incidents/${encodeURIComponent(id)}`,
    10000,
  );
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  if (!data) return <ErrorNote error={error ?? null} />;
  const i = data.incident;
  const h = i.hypothesis;
  const act = async (path: string, body?: unknown) => {
    try {
      await api(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
      setMsg("done");
      reload();
    } catch (e) {
      setMsg(String(e));
    }
  };
  return (
    <div className="grid">
      <Card title={`${i.id}: ${h.title}`}>
        <p>
          <Badge state={i.status} /> <Badge state={i.severity} /> confidence <b>{h.confidence}</b> · episode {i.episode}
        </p>
        <p>
          <b>Hypothesis:</b> {h.cause}
        </p>
        {h.affected_nodes.length > 0 && (
          <p>
            <b>Affected nodes:</b> {h.affected_nodes.join(", ")}
          </p>
        )}
        {h.scope_assets.length > 0 && (
          <p>
            <b>Scope:</b> {h.scope_assets.join(", ")}
          </p>
        )}
        <h3>Supporting evidence</h3>
        <ul>{h.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
        {h.contradicting.length > 0 && (
          <>
            <h3>Contradicting evidence</h3>
            <ul>{h.contradicting.map((e) => <li key={e}>{e}</li>)}</ul>
          </>
        )}
        <h3>Competing explanations</h3>
        <ul>{h.alternatives.map((e) => <li key={e}>{e}</li>)}</ul>
        <p>
          <b>Next useful check:</b> {h.next_check}
        </p>
        <div className="controls">
          <button onClick={() => act(`/api/v1/incidents/${i.id}/ack`)} disabled={i.acknowledged}>
            Acknowledge
          </button>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Operator note" aria-label="Operator note" maxLength={2000} />
          <button onClick={() => note && act(`/api/v1/incidents/${i.id}/notes`, { note })}>Add note</button>
          {msg && <span className="muted">{msg}</span>}
        </div>
      </Card>
      <Card title="Timeline">
        <ol className="timeline">
          {data.timeline.map((t, k) => (
            <li key={k}>
              {utc(t.at)} — <Badge state={t.kind === "resolved" ? "resolved" : t.kind === "recovering" ? "recovering" : "open"} /> {t.kind} (episode {t.episode}, {t.severity})
            </li>
          ))}
          {i.notes?.map((n, k) => (
            <li key={`n${k}`}>
              {utc(n.at)} — note by {n.actor}: {n.note}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
