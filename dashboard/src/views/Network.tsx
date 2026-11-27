import { useState } from "react";
import { Card, Empty, ErrorNote } from "../components";
import { useApi } from "../lib/hooks";
import { segments, type Series } from "../lib/series";

interface Catalog {
  series: Array<{ target: string; vantage: string }>;
}

const W = 900;
const H = 220;
const PAD = 40;

function Chart({ series, metric, unit }: { series: Series[]; metric: "p95_ms" | "p50_ms" | "loss_pct"; unit: string }) {
  const pts = series.flatMap((s) => s.points);
  if (pts.length === 0) return <Empty>No measurements in this period.</Empty>;
  const t0 = Math.min(...pts.map((p) => p.t));
  const t1 = Math.max(...pts.map((p) => p.t)) || t0 + 1;
  const vals = pts.map((p) => p[metric]).filter((v): v is number => v !== null);
  const vmax = Math.max(1, ...vals) * 1.1;
  const x = (t: number) => PAD + ((t - t0) / Math.max(1, t1 - t0)) * (W - 2 * PAD);
  const y = (v: number) => H - PAD - (v / vmax) * (H - 2 * PAD);
  const colors = ["#2563eb", "#16a34a", "#d97706", "#9333ea", "#dc2626", "#0891b2", "#4b5563"];
  return (
    <figure>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${metric} over time`} className="chart">
        <line x1={PAD} y1={H - PAD} x2={W - PAD} y2={H - PAD} className="axis" />
        <line x1={PAD} y1={PAD} x2={PAD} y2={H - PAD} className="axis" />
        <text x={4} y={PAD}>{`${vmax.toFixed(0)} ${unit}`}</text>
        <text x={4} y={H - PAD}>0</text>
        <text x={PAD} y={H - 8}>{new Date(t0).toISOString().slice(11, 16)}Z</text>
        <text x={W - PAD - 40} y={H - 8}>{new Date(t1).toISOString().slice(11, 16)}Z</text>
        {series.map((s, i) =>
          segments(s.points, s.resolution_s, (p) => p[metric]).map((seg, j) => (
            <polyline
              key={`${s.vantage}-${j}`}
              fill="none"
              stroke={colors[i % colors.length]}
              strokeWidth={1.5}
              points={seg.map(([t, v]) => `${x(t)},${y(v)}`).join(" ")}
            />
          )),
        )}
      </svg>
      <figcaption>
        {series.map((s, i) => (
          <span key={s.vantage} style={{ color: colors[i % colors.length] }}>
            ■ {s.vantage === "central" ? "wired (central)" : s.vantage}{" "}
          </span>
        ))}
        <span className="muted"> · gaps are shown, never bridged · resolution {series[0]?.resolution_s ?? "?"} s</span>
      </figcaption>
    </figure>
  );
}

export function Network() {
  const cat = useApi<Catalog>("/api/v1/metrics/catalog", 60000);
  const targets = [...new Set((cat.data?.series ?? []).map((s) => s.target))].sort();
  const [target, setTarget] = useState<string>("gw-icmp");
  const [hours, setHours] = useState(6);
  const q = useApi<{ series: Series[] }>(`/api/v1/metrics/query?target=${encodeURIComponent(target)}&hours=${hours}&max_points=600`, 30000);
  return (
    <div className="grid">
      <Card
        title="Network timeline"
        actions={
          <div className="controls">
            <label>
              Target{" "}
              <select value={target} onChange={(e) => setTarget(e.target.value)}>
                {(targets.length ? targets : [target]).map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
            <label>
              Period{" "}
              <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
                {[1, 6, 24, 72, 168].map((h) => (
                  <option key={h} value={h}>
                    {h} h
                  </option>
                ))}
              </select>
            </label>
          </div>
        }
      >
        <ErrorNote error={q.error} />
        <h3>RTT p95 by vantage</h3>
        <Chart series={q.data?.series ?? []} metric="p95_ms" unit="ms" />
        <h3>RTT median</h3>
        <Chart series={q.data?.series ?? []} metric="p50_ms" unit="ms" />
        <h3>Loss (timeouts / eligible probes)</h3>
        <Chart series={q.data?.series ?? []} metric="loss_pct" unit="%" />
      </Card>
    </div>
  );
}
