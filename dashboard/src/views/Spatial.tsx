import { useMemo, useState } from "react";
import { Badge, Card, Empty, ErrorNote } from "../components";
import { bounds, centroid, idw, pointInPolygon, type Anchor, type Pt } from "../lib/geometry";
import { age, ms } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { Room } from "../types";

interface Rooms {
  floors: Array<{ id: string; name: string; scale_m: number }>;
  rooms: Room[];
  room_edges: Array<{ from: string; to: string }>;
  nodes: Array<{ id: string; room: string | null; position: [number, number, number] | null }>;
}

interface Coverage {
  anchors: Array<{ node: string; bssid: string; ap: string | null; mean_dbm: number; samples: number; position: [number, number, number] | null; last_at: number }>;
}

interface Loc {
  device_id: string;
  room_id: string | null;
  last_known_room: string | null;
  confidence: number;
  state: string;
  age_ms: number | null;
  calibrated: boolean;
  model_revision: number;
  reason: string;
}

/** dBm -> fill colour. Unknown regions are left hatched, never coloured. */
function rssiColor(v: number): string {
  const t = Math.max(0, Math.min(1, (v + 90) / 40));
  return `hsl(${Math.round(t * 120)}, 70%, 55%)`;
}

export function FloorPlan() {
  const r = useApi<Rooms>("/api/v1/rooms");
  const cov = useApi<Coverage>("/api/v1/coverage", 30000);
  const loc = useApi<{ location_enabled: boolean; locations: Loc[] }>("/api/v1/locations/current", 5000);
  const [layer, setLayer] = useState<"coverage" | "none">("coverage");
  const [maxDist, setMaxDist] = useState(4);
  const rooms = useMemo(() => r.data?.rooms.filter((x) => x.polygon.length >= 3) ?? [], [r.data]);
  const anchors: Anchor[] = (cov.data?.anchors ?? [])
    .filter((a) => a.position)
    .map((a) => ({ x: a.position?.[0] ?? 0, y: a.position?.[1] ?? 0, value: a.mean_dbm }));
  const b = bounds(rooms.map((x) => x.polygon));
  const pad = 1;
  const vw = b.maxX - b.minX + 2 * pad;
  const vh = b.maxY - b.minY + 2 * pad;
  const cells: Array<{ x: number; y: number; v: number | null }> = [];
  if (layer === "coverage" && rooms.length) {
    const step = 0.5;
    for (let x = b.minX; x < b.maxX; x += step) {
      for (let y = b.minY; y < b.maxY; y += step) {
        const p: Pt = [x + step / 2, y + step / 2];
        if (!rooms.some((room) => pointInPolygon(p, room.polygon))) continue;
        const v = idw(p, anchors, maxDist);
        cells.push({ x, y, v: v ? v.value : null });
      }
    }
  }
  return (
    <div className="grid">
      <Card
        title="Floor plan"
        actions={
          <div className="controls">
            <label>
              Layer{" "}
              <select value={layer} onChange={(e) => setLayer(e.target.value as "coverage" | "none")}>
                <option value="coverage">2.4 GHz coverage (interpolated)</option>
                <option value="none">rooms only</option>
              </select>
            </label>
            <label>
              Interpolation limit{" "}
              <input type="number" min={1} max={15} value={maxDist} onChange={(e) => setMaxDist(Number(e.target.value))} /> m
            </label>
          </div>
        }
      >
        <ErrorNote error={r.error} />
        {rooms.length === 0 ? (
          <Empty>No room polygons configured. Add rooms with polygons (meters) in the site configuration to draw the floor plan; nothing is invented.</Empty>
        ) : (
          <svg viewBox={`${b.minX - pad} ${b.minY - pad} ${vw} ${vh}`} className="floor" role="img" aria-label="floor plan">
            <defs>
              <pattern id="hatch" width="0.4" height="0.4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <line x1="0" y1="0" x2="0" y2="0.4" stroke="#bbb" strokeWidth="0.08" />
              </pattern>
            </defs>
            {rooms.map((room) => (
              <polygon key={room.id} points={room.polygon.map((p) => p.join(",")).join(" ")} fill="url(#hatch)" stroke="#444" strokeWidth={0.05} />
            ))}
            {cells.map((c, i) =>
              c.v === null ? null : <rect key={i} x={c.x} y={c.y} width={0.5} height={0.5} fill={rssiColor(c.v)} opacity={0.55} />,
            )}
            {rooms.map((room) => {
              const [cx, cy] = centroid(room.polygon);
              const here = (loc.data?.locations ?? []).filter((l) => l.state === "located" && l.room_id === room.id);
              return (
                <g key={room.id}>
                  <text x={cx} y={cy} fontSize={0.45} textAnchor="middle">
                    {room.name}
                  </text>
                  {here.map((l, k) => (
                    <text key={l.device_id} x={cx} y={cy + 0.6 * (k + 1)} fontSize={0.35} textAnchor="middle">
                      {l.device_id} ({Math.round(l.confidence * 100)}%, room-level)
                    </text>
                  ))}
                </g>
              );
            })}
            {r.data?.nodes
              .filter((n) => n.position)
              .map((n) => (
                <g key={n.id}>
                  <circle cx={n.position?.[0]} cy={n.position?.[1]} r={0.2} fill="#111" />
                  <text x={(n.position?.[0] ?? 0) + 0.3} y={n.position?.[1]} fontSize={0.35}>
                    {n.id}
                  </text>
                </g>
              ))}
          </svg>
        )}
        <p className="muted">
          Coloured cells are inverse-distance interpolation between measured node anchors (2.4 GHz only) and are a visualization, not
          measurements. Hatched areas have no anchor within {maxDist} m: no measurement exists there. Device positions are room-level
          only; no precise person coordinate is ever drawn.
        </p>
      </Card>
      <Card title="Measured anchors">
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>AP</th>
              <th>Mean RSSI</th>
              <th>Samples</th>
              <th>Last</th>
            </tr>
          </thead>
          <tbody>
            {(cov.data?.anchors ?? []).map((a) => (
              <tr key={`${a.node}${a.bssid}`}>
                <td>{a.node}</td>
                <td>{a.ap ?? "unmapped BSSID"}</td>
                <td>{a.mean_dbm.toFixed(1)} dBm</td>
                <td>{a.samples}</td>
                <td>{age(a.last_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

export function Devices() {
  const d = useApi<{ location_enabled: boolean; devices: Array<{ id: string; kind: string; name: string; consent: boolean; matcher_type: string; location: Loc | null }> }>(
    "/api/v1/devices",
    5000,
  );
  if (!d.data) return <ErrorNote error={d.error ?? null} />;
  return (
    <Card title="Enrolled devices">
      {!d.data.location_enabled && <p className="warnbox">Location processing is disabled in the site configuration. No BLE data is retained.</p>}
      {d.data.devices.length === 0 ? (
        <Empty>No enrolled devices. Only explicitly enrolled, consenting devices are ever tracked; unknown phones are never listed.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Kind</th>
              <th>Consent</th>
              <th>State</th>
              <th>Room</th>
              <th>Confidence</th>
              <th>Model</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {d.data.devices.map((x) => (
              <tr key={x.id}>
                <td>{x.name}</td>
                <td>{x.kind}</td>
                <td>{x.consent ? "yes" : "no"}</td>
                <td>
                  <Badge state={x.location?.state ?? (d.data?.location_enabled ? "not_observed" : "disabled")} />
                </td>
                <td>{x.location?.room_id ?? (x.location?.last_known_room ? `last known: ${x.location.last_known_room}` : "—")}</td>
                <td>{x.location ? `${Math.round(x.location.confidence * 100)}%` : "—"}</td>
                <td>{x.location ? `${x.location.calibrated ? "calibrated" : "uncalibrated"} r${x.location.model_revision}` : "—"}</td>
                <td className="muted">{x.location?.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

export function Topology() {
  const t = useApi<{ nodes: Array<{ id: string; kind: string; health?: string; liveness?: string; incidents?: string[]; rssi_dbm?: number | null }>; edges: Array<{ from: string; to: string; type: string; source: string }> }>(
    "/api/v1/topology",
    10000,
  );
  if (!t.data) return <ErrorNote error={t.error ?? null} />;
  // Layered layout: depth = longest hard-parent chain.
  const parents = new Map<string, string[]>();
  for (const e of t.data.edges) parents.set(e.from, [...(parents.get(e.from) ?? []), e.to]);
  const depth = new Map<string, number>();
  const d = (id: string, guard = 0): number => {
    if (depth.has(id)) return depth.get(id) ?? 0;
    const ps = parents.get(id) ?? [];
    const v = guard > 20 || ps.length === 0 ? 0 : 1 + Math.max(...ps.map((p) => d(p, guard + 1)));
    depth.set(id, v);
    return v;
  };
  t.data.nodes.forEach((n) => d(n.id));
  const layers = new Map<number, string[]>();
  for (const n of t.data.nodes) layers.set(d(n.id), [...(layers.get(d(n.id)) ?? []), n.id]);
  const pos = new Map<string, [number, number]>();
  for (const [lvl, ids] of layers) ids.forEach((id, i) => pos.set(id, [60 + i * 150, 50 + lvl * 90]));
  const width = Math.max(...[...layers.values()].map((l) => l.length)) * 150 + 60;
  const height = (Math.max(...layers.keys()) + 1) * 90 + 40;
  const byId = new Map(t.data.nodes.map((n) => [n.id, n]));
  return (
    <Card title="Topology">
      <svg viewBox={`0 0 ${width} ${height}`} className="topo" role="img" aria-label="topology graph">
        {t.data.edges.map((e, i) => {
          const a = pos.get(e.from);
          const b = pos.get(e.to);
          if (!a || !b) return null;
          return <line key={i} x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} className={`edge ${e.type} ${e.source}`} />;
        })}
        {t.data.nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          const state = n.health ?? n.liveness ?? "unknown";
          return (
            <g key={n.id} transform={`translate(${p[0]},${p[1]})`}>
              <circle r={14} className={`tnode tone-${state}`} />
              <text y={30} textAnchor="middle" fontSize={11}>
                {n.id}
              </text>
              <text y={44} textAnchor="middle" fontSize={9} className="muted">
                {n.kind} · {state}
                {n.incidents && n.incidents.length ? ` · ${n.incidents.length} incident` : ""}
              </text>
            </g>
          );
        })}
      </svg>
      <p className="muted">
        Solid: configured hard dependency · dashed: redundant alternative · dotted: observed association (time-limited). {byId.size} elements.
      </p>
    </Card>
  );
}

export function Diagnostics() {
  const dns = useApi<{ matrix: Array<{ vantage: string; target: string; health: string; reason: string; wired: boolean; stats: { p95_ms: number | null; eligible: number; timeouts: number; dns_bad: number } }> }>(
    "/api/v1/diagnostics/dns",
    10000,
  );
  const rec = useApi<{ recommendations: Array<{ id: string; title: string; confidence: string; evidence: string[]; expected_effect: string; alternatives: string[]; verification: string }> }>(
    "/api/v1/recommendations",
    30000,
  );
  return (
    <div className="grid">
      <Card title="DNS matrix (resolver × vantage)">
        <ErrorNote error={dns.error} />
        <table>
          <thead>
            <tr>
              <th>Vantage</th>
              <th>Probe</th>
              <th>Health</th>
              <th>p95</th>
              <th>Timeouts</th>
              <th>Bad answers</th>
              <th>Eligible</th>
            </tr>
          </thead>
          <tbody>
            {(dns.data?.matrix ?? []).map((m) => (
              <tr key={m.vantage + m.target}>
                <td>{m.wired ? "wired (central)" : m.vantage}</td>
                <td>{m.target}</td>
                <td>
                  <Badge state={m.health} />
                </td>
                <td>{ms(m.stats.p95_ms)}</td>
                <td>{m.stats.timeouts}</td>
                <td>{m.stats.dns_bad}</td>
                <td>{m.stats.eligible}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card title="Advisory recommendations">
        <p className="muted">Advisory only — nothing is changed automatically on the router, APs or switches.</p>
        {(rec.data?.recommendations ?? []).length === 0 && <Empty>No recommendations from current evidence.</Empty>}
        <ul className="list">
          {(rec.data?.recommendations ?? []).map((x) => (
            <li key={x.id}>
              <b>{x.title}</b> <span className="muted">(confidence {x.confidence})</span>
              <div>Evidence: {x.evidence.join("; ")}</div>
              <div>Expected effect: {x.expected_effect}</div>
              <div className="muted">Alternatives: {x.alternatives.join("; ")} · Verify: {x.verification}</div>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
