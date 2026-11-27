import { Badge, Card, ErrorNote, Stat } from "../components";
import { age, dbm, ms, pct, UNKNOWN } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { SiteStatus, TargetSummary } from "../types";

function worst(targets: TargetSummary[], kind: string[]): TargetSummary | undefined {
  return targets
    .filter((t) => kind.includes(t.kind) && t.stats.p95_ms !== null)
    .sort((a, b) => (b.stats.p95_ms ?? 0) - (a.stats.p95_ms ?? 0))[0];
}

export function Overview() {
  const { data, error } = useApi<SiteStatus>("/api/v1/site/status", 5000);
  if (!data) return <ErrorNote error={error ?? null} />;
  const wireless = worst(data.targets.filter((t) => t.vantage !== "central"), ["icmp", "udp_echo"]);
  const dns = worst(data.targets, ["dns"]);
  const loss = data.targets.filter((t) => t.kind === "icmp" || t.kind === "udp_echo");
  const el = loss.reduce((s, t) => s + t.stats.eligible, 0);
  const to = loss.reduce((s, t) => s + t.stats.timeouts, 0);
  return (
    <div className="grid">
      <ErrorNote error={error} />
      <Card title="Site">
        <div className="stats">
          <Stat label="Ingestion" value={data.ingestion_ok ? "ok" : "DOWN"} hint={data.mqtt_connected ? "broker connected" : "broker disconnected"} />
          <Stat label="Health score" value={data.score.value === null ? UNKNOWN : data.score.value.toFixed(0)} hint={`coverage ${(data.score.coverage * 100).toFixed(0)}% · v${data.score.version}`} />
          <Stat label="Worst wireless p95" value={ms(wireless?.stats.p95_ms)} hint={wireless ? `${wireless.vantage} → ${wireless.target}` : "no data"} />
          <Stat label="DNS p95" value={ms(dns?.stats.p95_ms)} hint={dns ? `${dns.vantage} → ${dns.target}` : "no data"} />
          <Stat label="Probe loss (5 min)" value={el >= 20 ? pct((to * 100) / el, 2) : UNKNOWN} hint={`${to}/${el} eligible probes`} />
          <Stat label="Desired config rev" value={String(data.desired_revision)} />
        </div>
      </Card>
      <Card title={`Active incidents (${data.active_incidents.length})`}>
        {data.active_incidents.length === 0 ? (
          <p className="empty">No active incidents.</p>
        ) : (
          <ul className="list">
            {data.active_incidents.map((i) => (
              <li key={i.id}>
                <Badge state={i.status} /> <Badge state={i.severity} /> <a href={`#/incidents/${i.id}`}>{i.hypothesis.title}</a>
                <div className="muted">
                  {i.hypothesis.cause} · confidence {i.hypothesis.confidence} · opened {age(i.opened_at)}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Nodes">
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>State</th>
              <th>Room</th>
              <th>RSSI</th>
              <th>Last data</th>
            </tr>
          </thead>
          <tbody>
            {data.nodes.map((n) => (
              <tr key={n.id}>
                <td>
                  <a href={`#/nodes/${n.id}`}>{n.id}</a>
                </td>
                <td>
                  <Badge state={n.liveness} />
                </td>
                <td>{n.room ?? "unplaced"}</td>
                <td>{n.liveness === "online" ? dbm(n.rssi_dbm) : UNKNOWN}</td>
                <td>{age(n.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card title="Targets by vantage (5-minute window)">
        <table>
          <thead>
            <tr>
              <th>Vantage</th>
              <th>Target</th>
              <th>Health</th>
              <th>p50</th>
              <th>p95</th>
              <th>Loss</th>
              <th>n</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {data.targets.map((t) => (
              <tr key={`${t.vantage}/${t.target}`}>
                <td>{t.vantage === "central" ? "wired (central)" : t.vantage}</td>
                <td>{t.target}</td>
                <td>
                  <Badge state={t.health} />
                </td>
                <td>{ms(t.stats.p50_ms)}</td>
                <td className={t.stats.successes < 20 ? "lowconf" : ""} title={t.stats.successes < 20 ? "fewer than 20 samples" : ""}>
                  {ms(t.stats.p95_ms)}
                </td>
                <td>{t.stats.eligible > 0 ? pct(t.stats.loss_pct) : UNKNOWN}</td>
                <td>{t.stats.eligible}</td>
                <td className="muted">{t.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
