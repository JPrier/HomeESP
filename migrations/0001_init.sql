-- Home Observatory schema v1. All timestamps are UTC integer milliseconds.
-- RTTs are microseconds; NULL means "not measured" (never 0 for a failure).

CREATE TABLE nodes (
  id               TEXT PRIMARY KEY,
  first_seen       INTEGER,
  last_seen        INTEGER,
  chip             TEXT,
  fw_version       TEXT,
  profile          TEXT,
  features         INTEGER,
  flash_kb         INTEGER,
  capabilities     TEXT,               -- JSON
  applied_revision INTEGER,
  config_state     TEXT,               -- applied | rejected | pending
  config_reason    INTEGER,
  desired_revision INTEGER
);

CREATE TABLE node_boots (
  node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  boot_id    TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  PRIMARY KEY (node_id, boot_id)
);

CREATE TABLE batches (
  id              INTEGER PRIMARY KEY,
  site_id         TEXT NOT NULL,
  node_id         TEXT NOT NULL,
  boot_id         TEXT NOT NULL,
  sequence        INTEGER NOT NULL,
  kind            INTEGER NOT NULL,
  flags           INTEGER NOT NULL,
  received_at     INTEGER NOT NULL,
  sent_mono_ms    INTEGER NOT NULL,
  config_revision INTEGER NOT NULL,
  record_count    INTEGER NOT NULL,
  bytes           INTEGER NOT NULL,
  clock_uncertainty_ms INTEGER,
  UNIQUE (site_id, node_id, boot_id, sequence)
);
CREATE INDEX batches_received ON batches(received_at);

CREATE TABLE probe_results (
  batch_id       INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx            INTEGER NOT NULL,
  vantage        TEXT NOT NULL,
  observed_at    INTEGER NOT NULL,
  uncertainty_ms INTEGER NOT NULL,
  target_id      TEXT NOT NULL,
  kind           TEXT NOT NULL,
  outcome        TEXT NOT NULL,
  rtt_us         INTEGER,
  scan_overlap   INTEGER NOT NULL,
  dscp           INTEGER NOT NULL,
  sched_late_ms  INTEGER NOT NULL,
  error_code     INTEGER NOT NULL,
  dns_rcode      INTEGER,
  dns_answer     TEXT,
  dns_transport  TEXT,
  via_bssid      TEXT,
  PRIMARY KEY (batch_id, idx),
  CHECK (rtt_us IS NULL OR outcome = 'success'),
  CHECK (rtt_us IS NULL OR rtt_us >= 0)
);
CREATE INDEX probe_target_time ON probe_results(target_id, vantage, observed_at);
CREATE INDEX probe_time ON probe_results(observed_at);

CREATE TABLE wifi_samples (
  batch_id    INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  node_id     TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  status      TEXT NOT NULL,
  rssi_dbm    INTEGER,
  channel     INTEGER NOT NULL,
  bssid       TEXT,
  assoc_gen   INTEGER NOT NULL,
  PRIMARY KEY (batch_id, idx)
);
CREATE INDEX wifi_node_time ON wifi_samples(node_id, observed_at);

CREATE TABLE ap_scan_samples (
  batch_id       INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx            INTEGER NOT NULL,
  node_id        TEXT NOT NULL,
  observed_at    INTEGER NOT NULL,
  scan_id        INTEGER NOT NULL,
  duration_ms    INTEGER NOT NULL,
  completeness   TEXT NOT NULL,
  channel_counts TEXT NOT NULL,   -- JSON array of 14 counts (non-identifying)
  samples        TEXT NOT NULL,   -- JSON [{bssid, channel, rssi_dbm}] tracked infrastructure only
  PRIMARY KEY (batch_id, idx)
);
CREATE INDEX scan_node_time ON ap_scan_samples(node_id, observed_at);

CREATE TABLE lifecycle_events (
  batch_id    INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  node_id     TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  event       TEXT NOT NULL,
  reason      INTEGER NOT NULL,
  prior_bssid TEXT,
  new_bssid   TEXT,
  duration_ms INTEGER,
  PRIMARY KEY (batch_id, idx)
);
CREATE INDEX life_node_time ON lifecycle_events(node_id, observed_at);

CREATE TABLE node_health (
  batch_id     INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx          INTEGER NOT NULL,
  node_id      TEXT NOT NULL,
  observed_at  INTEGER NOT NULL,
  uptime_s     INTEGER NOT NULL,
  heap_free    INTEGER NOT NULL,
  heap_min     INTEGER NOT NULL,
  heap_max_block INTEGER NOT NULL,
  heap_frag_pct  INTEGER NOT NULL,
  reset_reason INTEGER NOT NULL,
  queue_fill_pct INTEGER NOT NULL,
  drops_overflow INTEGER NOT NULL,
  drops_budget   INTEGER NOT NULL,
  drops_expired  INTEGER NOT NULL,
  missed_schedules INTEGER NOT NULL,
  loop_lag_max_ms  INTEGER NOT NULL,
  reconnects   INTEGER NOT NULL,
  tx_bytes     INTEGER NOT NULL,
  tx_frames    INTEGER NOT NULL,
  fw_version   TEXT NOT NULL,
  PRIMARY KEY (batch_id, idx)
);
CREATE INDEX health_node_time ON node_health(node_id, observed_at);

-- Enrolled devices only; unmatched identifiers never reach storage.
CREATE TABLE ble_windows (
  batch_id    INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  node_id     TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  device_id   TEXT NOT NULL,
  window_ms   INTEGER NOT NULL,
  count       INTEGER NOT NULL,
  rssi_min    INTEGER NOT NULL,
  rssi_max    INTEGER NOT NULL,
  rssi_mean   REAL NOT NULL,
  coverage    INTEGER NOT NULL,
  PRIMARY KEY (batch_id, idx)
);
CREATE INDEX ble_device_time ON ble_windows(device_id, observed_at);

CREATE TABLE sensor_samples (
  batch_id    INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  node_id     TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  sensor_id   TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  unit        INTEGER NOT NULL,
  value       REAL NOT NULL,
  quality     INTEGER NOT NULL,
  calibration_rev INTEGER NOT NULL,
  PRIMARY KEY (batch_id, idx)
);

-- Mergeable probe rollups (histogram JSON), minute (60) and hour (3600) resolution.
CREATE TABLE rollups (
  target_id      TEXT NOT NULL,
  vantage        TEXT NOT NULL,
  resolution_s   INTEGER NOT NULL,
  bucket_start   INTEGER NOT NULL,
  samples        INTEGER NOT NULL,
  eligible       INTEGER NOT NULL,
  successes      INTEGER NOT NULL,
  timeouts       INTEGER NOT NULL,
  other_failures INTEGER NOT NULL,
  skipped        INTEGER NOT NULL,
  dns_bad        INTEGER NOT NULL,
  rtt_sum_us     INTEGER NOT NULL,
  rtt_min_us     INTEGER,
  rtt_max_us     INTEGER,
  hist           TEXT NOT NULL,
  PRIMARY KEY (target_id, vantage, resolution_s, bucket_start)
);
CREATE INDEX rollup_time ON rollups(resolution_s, bucket_start);

CREATE TABLE incidents (
  id               TEXT PRIMARY KEY,
  key              TEXT NOT NULL,
  status           TEXT NOT NULL,
  severity         TEXT NOT NULL,
  episode          INTEGER NOT NULL,
  flaps            INTEGER NOT NULL,
  opened_at        INTEGER NOT NULL,
  last_evidence_at INTEGER NOT NULL,
  resolved_at      INTEGER,
  acknowledged     INTEGER NOT NULL DEFAULT 0,
  hypothesis       TEXT NOT NULL,
  notes            TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX incidents_status ON incidents(status, opened_at);

CREATE TABLE incident_events (
  id          INTEGER PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  episode     INTEGER NOT NULL,
  severity    TEXT NOT NULL,
  at          INTEGER NOT NULL,
  title       TEXT NOT NULL,
  summary     TEXT NOT NULL
);
CREATE INDEX incident_events_inc ON incident_events(incident_id, at);

CREATE TABLE outbox (
  id              INTEGER PRIMARY KEY,
  dedup_key       TEXT NOT NULL UNIQUE,     -- incident_id|event|episode|recipient
  notifier        TEXT NOT NULL,
  payload         TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL,            -- pending | sent | failed | suppressed
  last_error      TEXT,
  delivered_at    INTEGER
);
CREATE INDEX outbox_due ON outbox(status, next_attempt_at);

CREATE TABLE delivery_attempts (
  outbox_id INTEGER NOT NULL REFERENCES outbox(id) ON DELETE CASCADE,
  at        INTEGER NOT NULL,
  ok        INTEGER NOT NULL,
  error     TEXT
);

CREATE TABLE location_state (
  device_id  TEXT PRIMARY KEY,
  updated_at INTEGER NOT NULL,
  estimate   TEXT NOT NULL
);

CREATE TABLE location_transitions (
  id             INTEGER PRIMARY KEY,
  device_id      TEXT NOT NULL,
  at             INTEGER NOT NULL,
  room_id        TEXT,
  state          TEXT NOT NULL,
  confidence     REAL NOT NULL,
  model_revision INTEGER NOT NULL
);
CREATE INDEX loc_device_time ON location_transitions(device_id, at);

CREATE TABLE calibration_sessions (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL,
  room_id    TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER,
  status     TEXT NOT NULL,
  heldout    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE models (
  revision   INTEGER PRIMARY KEY,
  created_at INTEGER NOT NULL,
  model      TEXT NOT NULL,
  evaluation TEXT,
  active     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_events (
  id     INTEGER PRIMARY KEY,
  at     INTEGER NOT NULL,
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);

CREATE TABLE config_revisions (
  revision INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  actor    TEXT NOT NULL,
  sha256   TEXT NOT NULL,
  yaml     TEXT NOT NULL,
  active   INTEGER NOT NULL DEFAULT 0
);

-- Rejected frames: sanitized (first 32 bytes only, never BLE payloads).
CREATE TABLE dlq (
  id      INTEGER PRIMARY KEY,
  at      INTEGER NOT NULL,
  node_id TEXT,
  topic   TEXT NOT NULL,
  reason  TEXT NOT NULL,
  size    INTEGER NOT NULL,
  head_hex TEXT
);

CREATE TABLE kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
