import { useState } from "react";
import { Badge, Card, ErrorNote } from "../components";
import { api } from "../lib/api";
import { age, utc } from "../lib/format";
import { useApi } from "../lib/hooks";

interface NodeRow {
  id: string;
  room: string | null;
  board: string | null;
  liveness: string | null;
  state: { rssi_dbm: number | null; channel: number | null; ap: string | null; boot_id: string | null; reconnects: number } | null;
  inventory: { fw_version: string | null; chip: string | null; applied_revision: number | null; desired_revision: number | null; config_state: string | null; boots: number; last_seen: number | null; flash_kb: number | null } | null;
}

export function Nodes() {
  const { data, error } = useApi<{ nodes: NodeRow[] }>("/api/v1/nodes", 5000);
  return (
    <Card title="Node management">
      <ErrorNote error={error} />
      <table>
        <thead>
          <tr>
            <th>Node</th>
            <th>State</th>
            <th>Chip / FW</th>
            <th>Config (applied / desired)</th>
            <th>AP · ch · RSSI</th>
            <th>Boots</th>
            <th>Last data</th>
          </tr>
        </thead>
        <tbody>
          {data?.nodes.map((n) => (
            <tr key={n.id}>
              <td>
                <a href={`#/nodes/${n.id}`}>{n.id}</a>
              </td>
              <td>
                <Badge state={n.liveness} />
              </td>
              <td>
                {n.inventory?.chip ?? "?"} · {n.inventory?.fw_version ?? "?"}
              </td>
              <td>
                <Badge state={n.inventory?.config_state === "applied" && n.inventory.applied_revision === n.inventory.desired_revision ? "healthy" : n.inventory?.config_state ?? "unknown"} />{" "}
                {n.inventory?.applied_revision ?? "?"} / {n.inventory?.desired_revision ?? "?"}
              </td>
              <td>
                {n.state?.ap ?? "?"} · {n.state?.channel ?? "?"} · {n.state?.rssi_dbm ?? "?"} dBm
              </td>
              <td>{n.inventory?.boots ?? 0}</td>
              <td>{age(n.inventory?.last_seen ?? null)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

export function NodeDetail({ id }: { id: string }) {
  const { data, error } = useApi<{ health: Record<string, number | string> | null; events: Array<{ at: number; event: string; reason: number; duration_ms: number | null }>; latest_scan: { at: number; completeness: string; channel_counts: number[]; samples: Array<{ bssid: string; channel: number; rssi_dbm: number }> } | null }>(
    `/api/v1/nodes/${encodeURIComponent(id)}`,
    10000,
  );
  if (!data) return <ErrorNote error={error ?? null} />;
  return (
    <div className="grid">
      <Card title={`${id} health`}>
        {data.health ? (
          <dl className="kv">
            {Object.entries(data.health).map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{k === "at" ? utc(Number(v)) : String(v)}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="empty">No health report yet (sent every 60 s).</p>
        )}
      </Card>
      <Card title="Lifecycle events (latest 50)">
        <ul className="list">
          {data.events.map((e, i) => (
            <li key={i}>
              {utc(e.at)} — {e.event} (raw reason {e.reason}){e.duration_ms ? ` · outage ${e.duration_ms} ms` : ""}
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Latest passive scan">
        {data.latest_scan ? (
          <>
            <p>
              {utc(data.latest_scan.at)} · {data.latest_scan.completeness}
            </p>
            <p className="muted">Beacons per 2.4 GHz channel (non-identifying counts): {data.latest_scan.channel_counts.join(" ")}</p>
            <ul>
              {data.latest_scan.samples.map((s) => (
                <li key={s.bssid}>
                  {s.bssid} ch{s.channel} {s.rssi_dbm} dBm
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="empty">No scan yet.</p>
        )}
      </Card>
    </div>
  );
}

export function Settings() {
  const cfg = useApi<{ revision: number | null; sha256: string | null; yaml: string }>("/api/v1/admin/config");
  const ob = useApi<{ outbox: Array<{ id: number; notifier: string; status: string; attempts: number; created_at: number; last_error: string | null; dedup_key: string }> }>("/api/v1/outbox", 10000);
  const au = useApi<{ audit: Array<{ at: number; actor: string; action: string; target: string | null }> }>("/api/v1/audit", 30000);
  const [msg, setMsg] = useState<string | null>(null);
  const [yaml, setYaml] = useState<string | null>(null);
  const text = yaml ?? cfg.data?.yaml ?? "";
  const submit = async (dry: boolean) => {
    try {
      const r = await api<Record<string, unknown>>("/api/v1/admin/config", {
        method: "PUT",
        headers: cfg.data?.revision ? { "If-Match": String(cfg.data.revision) } : {},
        body: JSON.stringify({ yaml: text, dry_run: dry }),
      });
      setMsg(JSON.stringify(r));
    } catch (e) {
      setMsg(String(e));
    }
  };
  return (
    <div className="grid">
      <Card title={`Configuration (revision ${cfg.data?.revision ?? "?"})`}>
        <ErrorNote error={cfg.error} />
        <p className="muted">Secrets are never shown: the configuration only references secret files. Broker, server, notifier, integration and watchdog sections are read-only here.</p>
        <textarea value={text} onChange={(e) => setYaml(e.target.value)} rows={18} aria-label="configuration YAML" spellCheck={false} />
        <div className="controls">
          <button onClick={() => submit(true)}>Validate (dry run)</button>
          <button onClick={() => submit(false)}>Apply (requires restart)</button>
          <button
            onClick={async () => {
              try {
                setMsg(JSON.stringify(await api("/api/v1/notifications/test", { method: "POST" })));
                ob.reload();
              } catch (e) {
                setMsg(String(e));
              }
            }}
          >
            Send test notification
          </button>
        </div>
        {msg && <pre className="msg">{msg}</pre>}
      </Card>
      <Card title="Notification outbox">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Notifier</th>
              <th>Status</th>
              <th>Attempts</th>
              <th>Created</th>
              <th>Last error</th>
            </tr>
          </thead>
          <tbody>
            {ob.data?.outbox.map((o) => (
              <tr key={o.id}>
                <td title={o.dedup_key}>{o.id}</td>
                <td>{o.notifier}</td>
                <td>
                  <Badge state={o.status} />
                </td>
                <td>{o.attempts}</td>
                <td>{utc(o.created_at)}</td>
                <td className="muted">{o.last_error}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card title="Audit trail">
        <ul className="list">
          {au.data?.audit.map((a, i) => (
            <li key={i}>
              {utc(a.at)} — {a.actor}: {a.action} {a.target ?? ""}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
