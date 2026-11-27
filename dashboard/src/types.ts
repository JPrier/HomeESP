export interface WindowStats {
  samples: number;
  eligible: number;
  successes: number;
  timeouts: number;
  other_failures: number;
  skipped: number;
  loss_pct: number | null;
  p50_ms: number | null;
  p95_ms: number | null;
  p99_ms: number | null;
  jitter_ms: number | null;
  dns_bad: number;
  scan_overlap: number;
}

export interface TargetSummary {
  vantage: string;
  target: string;
  kind: string;
  asset: string | null;
  critical: boolean;
  health: string;
  reason: string;
  since: number;
  stats: WindowStats;
}

export interface Hypothesis {
  key: string;
  kind: string;
  severity: string;
  title: string;
  cause: string;
  confidence: string;
  scope_assets: string[];
  affected_nodes: string[];
  evidence: string[];
  contradicting: string[];
  alternatives: string[];
  next_check: string;
}

export interface Incident {
  id: string;
  key: string;
  status: string;
  severity: string;
  episode: number;
  flaps: number;
  opened_at: number;
  last_evidence_at?: number;
  resolved_at: number | null;
  acknowledged: boolean;
  hypothesis: Hypothesis;
}

export interface SiteStatus {
  site_id: string;
  now: string;
  generated_at: string;
  uptime_s: number;
  ingestion_ok: boolean;
  mqtt_connected: boolean;
  nodes: Array<{ id: string; liveness: string; room: string | null; rssi_dbm: number | null; last_seen: string | null }>;
  targets: TargetSummary[];
  active_incidents: Incident[];
  score: { version: number; value: number | null; coverage: number; worst_vantage: string | null; components: Array<[string, number | null]> };
  ingest: Record<string, unknown>;
  storage: Record<string, number> | null;
  desired_revision: number;
}

export interface Room {
  id: string;
  name: string;
  floor: string | null;
  polygon: Array<[number, number]>;
}
