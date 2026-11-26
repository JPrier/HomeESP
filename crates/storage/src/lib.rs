//! SQLite persistence (WAL, foreign keys, migrations). Blocking API: the server owns
//! one `Store` on a dedicated writer thread and a separate read-only connection pool
//! for queries, so slow API clients never block sensor intake.

use ho_domain::*;
use ho_logic::incidents::{Incident, IncidentEvent};
use ho_logic::location::LocationEstimate;
use ho_logic::stats::LogHistogram;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::Serialize;
use std::path::Path;

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../../../migrations/0001_init.sql"))];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database schema version {found} is newer than supported {supported}")]
    TooNew { found: i64, supported: i64 },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Metadata for one accepted frame.
#[derive(Debug, Clone)]
pub struct BatchMeta {
    pub site_id: String,
    pub node_id: String,
    pub boot_id: String,
    pub sequence: u64,
    pub kind: u8,
    pub flags: u8,
    pub received_at: UnixMs,
    pub sent_mono_ms: u64,
    pub config_revision: u64,
    pub record_count: u8,
    pub bytes: usize,
    pub clock_uncertainty_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted(i64),
    Duplicate,
}

/// A queued notification.
#[derive(Debug, Clone, Serialize)]
pub struct OutboxItem {
    pub id: i64,
    pub dedup_key: String,
    pub notifier: String,
    pub payload: String,
    pub attempts: i64,
    pub status: String,
    pub created_at: UnixMs,
    pub last_error: Option<String>,
}

/// One point of a metric series.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SeriesPoint {
    pub t: UnixMs,
    pub samples: i64,
    pub eligible: i64,
    pub loss_pct: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub dns_bad: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Series {
    pub target_id: String,
    pub vantage: String,
    pub resolution_s: i64,
    pub points: Vec<SeriesPoint>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RetentionReport {
    pub raw_batches: usize,
    pub rollups: usize,
    pub incidents: usize,
    pub locations: usize,
    pub outbox: usize,
}

pub struct Store {
    conn: Connection,
}

fn configure(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

impl Store {
    /// Open (creating if needed) and migrate.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        configure(&conn)?;
        let mut s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    /// Read-only connection for query workloads.
    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    fn migrate(&mut self) -> Result<()> {
        let current = self.schema_version()?;
        let latest = MIGRATIONS.last().map_or(0, |m| m.0);
        if current > latest {
            return Err(StoreError::TooNew { found: current, supported: latest });
        }
        for (v, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", v)?;
            tx.commit()?;
            tracing::info!(version = v, "applied migration");
        }
        Ok(())
    }

    // ------------------------------------------------------------ ingestion

    /// Durably insert a frame and its observations in one transaction. Duplicate
    /// `(site, node, boot, sequence)` is detected by the unique key and is a no-op.
    pub fn insert_frame(&mut self, b: &BatchMeta, obs: &[Observation]) -> Result<InsertOutcome> {
        let tx = self.conn.transaction()?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO batches (site_id,node_id,boot_id,sequence,kind,flags,received_at,sent_mono_ms,config_revision,record_count,bytes,clock_uncertainty_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                b.site_id,
                b.node_id,
                b.boot_id,
                b.sequence as i64,
                b.kind,
                b.flags,
                b.received_at,
                b.sent_mono_ms as i64,
                b.config_revision as i64,
                b.record_count,
                b.bytes as i64,
                b.clock_uncertainty_ms
            ],
        )?;
        if n == 0 {
            return Ok(InsertOutcome::Duplicate);
        }
        let batch_id = tx.last_insert_rowid();
        if b.node_id != "central" {
            tx.execute(
                "INSERT INTO nodes (id, first_seen, last_seen) VALUES (?1, ?2, ?2)
                 ON CONFLICT(id) DO UPDATE SET last_seen = max(coalesce(last_seen, 0), excluded.last_seen)",
                params![b.node_id, b.received_at],
            )?;
            tx.execute(
                "INSERT INTO node_boots (node_id, boot_id, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(node_id, boot_id) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)",
                params![b.node_id, b.boot_id, b.received_at],
            )?;
        }
        for o in obs {
            insert_obs(&tx, batch_id, o)?;
        }
        tx.commit()?;
        Ok(InsertOutcome::Inserted(batch_id))
    }

    pub fn record_dlq(&mut self, at: UnixMs, node: Option<&str>, topic: &str, reason: &str, payload: &[u8]) -> Result<()> {
        let head: String = payload.iter().take(32).map(|b| format!("{b:02x}")).collect();
        self.conn.execute(
            "INSERT INTO dlq (at,node_id,topic,reason,size,head_hex) VALUES (?1,?2,?3,?4,?5,?6)",
            params![at, node, topic, reason, payload.len() as i64, head],
        )?;
        // Bound the DLQ.
        self.conn.execute("DELETE FROM dlq WHERE id <= (SELECT max(id) - 1000 FROM dlq)", [])?;
        Ok(())
    }

    pub fn upsert_capabilities(&mut self, node: &str, at: UnixMs, chip: &str, fw: &str, profile: &str, features: u32, flash_kb: u32, json: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO nodes (id, first_seen, last_seen, chip, fw_version, profile, features, flash_kb, capabilities)
             VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET chip=excluded.chip, fw_version=excluded.fw_version, profile=excluded.profile,
               features=excluded.features, flash_kb=excluded.flash_kb, capabilities=excluded.capabilities",
            params![node, at, chip, fw, profile, features, flash_kb, json],
        )?;
        Ok(())
    }

    pub fn set_config_status(&mut self, node: &str, revision: u64, state: &str, reason: u8) -> Result<()> {
        self.conn.execute(
            "INSERT INTO nodes (id, applied_revision, config_state, config_reason) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET applied_revision=excluded.applied_revision, config_state=excluded.config_state, config_reason=excluded.config_reason",
            params![node, revision as i64, state, reason],
        )?;
        Ok(())
    }

    pub fn set_desired_revision(&mut self, node: &str, revision: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO nodes (id, desired_revision) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET desired_revision=excluded.desired_revision",
            params![node, revision as i64],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------ derived state

    /// Commit derived state + outbox atomically (spec §9.1).
    pub fn commit_derived(
        &mut self,
        incidents: &[Incident],
        events: &[IncidentEvent],
        outbox: &[(String, String, String, UnixMs, bool)],
        locations: &[LocationEstimate],
        checkpoint: Option<(&str, &str)>,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for i in incidents {
            tx.execute(
                "INSERT INTO incidents (id,key,status,severity,episode,flaps,opened_at,last_evidence_at,resolved_at,acknowledged,hypothesis)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                 ON CONFLICT(id) DO UPDATE SET status=excluded.status, severity=excluded.severity, episode=excluded.episode,
                   flaps=excluded.flaps, last_evidence_at=excluded.last_evidence_at, resolved_at=excluded.resolved_at,
                   acknowledged=max(incidents.acknowledged, excluded.acknowledged), hypothesis=excluded.hypothesis",
                params![
                    i.id,
                    i.key,
                    enum_str(&i.status)?,
                    enum_str(&i.severity)?,
                    i.episode,
                    i.flaps,
                    i.opened_at,
                    i.last_evidence_at,
                    i.resolved_at,
                    i.acknowledged,
                    serde_json::to_string(&i.hypothesis)?
                ],
            )?;
        }
        for e in events {
            tx.execute(
                "INSERT INTO incident_events (incident_id,kind,episode,severity,at,title,summary) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![e.incident_id, e.kind.as_str(), e.episode, enum_str(&e.severity)?, e.at, e.title, e.summary],
            )?;
        }
        for (key, notifier, payload, at, suppressed) in outbox {
            tx.execute(
                "INSERT OR IGNORE INTO outbox (dedup_key, notifier, payload, created_at, next_attempt_at, status) VALUES (?1,?2,?3,?4,?4,?5)",
                params![key, notifier, payload, at, if *suppressed { "suppressed" } else { "pending" }],
            )?;
        }
        for l in locations {
            tx.execute(
                "INSERT INTO location_state (device_id, updated_at, estimate) VALUES (?1,?2,?3)
                 ON CONFLICT(device_id) DO UPDATE SET updated_at=excluded.updated_at, estimate=excluded.estimate",
                params![l.device_id, l.observed_at.unwrap_or(0), serde_json::to_string(l)?],
            )?;
            tx.execute(
                "INSERT INTO location_transitions (device_id, at, room_id, state, confidence, model_revision) VALUES (?1,?2,?3,?4,?5,?6)",
                params![l.device_id, l.observed_at.unwrap_or(0), l.room_id, enum_str(&l.state)?, l.confidence, l.model_revision],
            )?;
        }
        if let Some((k, v)) = checkpoint {
            tx.execute("INSERT INTO kv (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![k, v])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM kv WHERE key=?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn kv_set(&mut self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT INTO kv (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value])?;
        Ok(())
    }

    // ------------------------------------------------------------ outbox

    /// Pending items due now (bounded).
    pub fn outbox_due(&self, now: UnixMs, limit: usize) -> Result<Vec<OutboxItem>> {
        let mut st = self.conn.prepare(
            "SELECT id,dedup_key,notifier,payload,attempts,status,created_at,last_error FROM outbox
             WHERE status='pending' AND next_attempt_at <= ?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = st.query_map(params![now, limit as i64], row_outbox)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn outbox_list(&self, status: Option<&str>, limit: usize) -> Result<Vec<OutboxItem>> {
        let mut st = self.conn.prepare(
            "SELECT id,dedup_key,notifier,payload,attempts,status,created_at,last_error FROM outbox
             WHERE (?1 IS NULL OR status=?1) ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![status, limit as i64], row_outbox)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Record a delivery attempt. `retry_at = None` with `ok=false` marks permanent failure.
    pub fn outbox_attempt(&mut self, id: i64, now: UnixMs, ok: bool, error: Option<&str>, retry_at: Option<UnixMs>) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO delivery_attempts (outbox_id, at, ok, error) VALUES (?1,?2,?3,?4)", params![id, now, ok, error])?;
        if ok {
            tx.execute("UPDATE outbox SET status='sent', attempts=attempts+1, delivered_at=?2, last_error=NULL WHERE id=?1", params![id, now])?;
        } else if let Some(r) = retry_at {
            tx.execute("UPDATE outbox SET attempts=attempts+1, next_attempt_at=?2, last_error=?3 WHERE id=?1", params![id, r, error])?;
        } else {
            tx.execute("UPDATE outbox SET status='failed', attempts=attempts+1, last_error=?2 WHERE id=?1", params![id, error])?;
        }
        tx.commit()?;
        Ok(())
    }

    // ------------------------------------------------------------ queries

    pub fn incidents(&self, status: Option<&str>, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT id,key,status,severity,episode,flaps,opened_at,last_evidence_at,resolved_at,acknowledged,hypothesis,notes
             FROM incidents WHERE (?1 IS NULL OR status=?1) ORDER BY opened_at DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![status, limit as i64], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?, "key": r.get::<_, String>(1)?, "status": r.get::<_, String>(2)?,
                "severity": r.get::<_, String>(3)?, "episode": r.get::<_, i64>(4)?, "flaps": r.get::<_, i64>(5)?,
                "opened_at": r.get::<_, i64>(6)?, "last_evidence_at": r.get::<_, i64>(7)?,
                "resolved_at": r.get::<_, Option<i64>>(8)?, "acknowledged": r.get::<_, bool>(9)?,
                "hypothesis": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(10)?).unwrap_or_default(),
                "notes": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(11)?).unwrap_or_default(),
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn incident_events(&self, incident_id: &str) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare("SELECT kind,episode,severity,at,title,summary FROM incident_events WHERE incident_id=?1 ORDER BY at, id")?;
        let rows = st.query_map([incident_id], |r| {
            Ok(serde_json::json!({"kind": r.get::<_, String>(0)?, "episode": r.get::<_, i64>(1)?, "severity": r.get::<_, String>(2)?,
                "at": r.get::<_, i64>(3)?, "title": r.get::<_, String>(4)?, "summary": r.get::<_, String>(5)?}))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn add_incident_note(&mut self, id: &str, at: UnixMs, actor: &str, note: &str) -> Result<bool> {
        let notes: Option<String> = self.conn.query_row("SELECT notes FROM incidents WHERE id=?1", [id], |r| r.get(0)).optional()?;
        let Some(notes) = notes else { return Ok(false) };
        let mut v: Vec<serde_json::Value> = serde_json::from_str(&notes).unwrap_or_default();
        v.push(serde_json::json!({"at": at, "actor": actor, "note": note}));
        self.conn.execute("UPDATE incidents SET notes=?2 WHERE id=?1", params![id, serde_json::to_string(&v)?])?;
        Ok(true)
    }

    pub fn acknowledge_incident(&mut self, id: &str) -> Result<bool> {
        Ok(self.conn.execute("UPDATE incidents SET acknowledged=1 WHERE id=?1", [id])? > 0)
    }

    pub fn nodes(&self) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT id,first_seen,last_seen,chip,fw_version,profile,features,flash_kb,applied_revision,config_state,config_reason,desired_revision,
                    (SELECT count(*) FROM node_boots b WHERE b.node_id = nodes.id)
             FROM nodes ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?, "first_seen": r.get::<_, Option<i64>>(1)?, "last_seen": r.get::<_, Option<i64>>(2)?,
                "chip": r.get::<_, Option<String>>(3)?, "fw_version": r.get::<_, Option<String>>(4)?, "profile": r.get::<_, Option<String>>(5)?,
                "features": r.get::<_, Option<i64>>(6)?, "flash_kb": r.get::<_, Option<i64>>(7)?,
                "applied_revision": r.get::<_, Option<i64>>(8)?, "config_state": r.get::<_, Option<String>>(9)?,
                "config_reason": r.get::<_, Option<i64>>(10)?, "desired_revision": r.get::<_, Option<i64>>(11)?,
                "boots": r.get::<_, i64>(12)?,
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn node_events(&self, node: &str, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT observed_at,event,reason,prior_bssid,new_bssid,duration_ms FROM lifecycle_events WHERE node_id=?1 ORDER BY observed_at DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![node, limit as i64], |r| {
            Ok(serde_json::json!({"at": r.get::<_, i64>(0)?, "event": r.get::<_, String>(1)?, "reason": r.get::<_, i64>(2)?,
                "prior_bssid": r.get::<_, Option<String>>(3)?, "new_bssid": r.get::<_, Option<String>>(4)?, "duration_ms": r.get::<_, Option<i64>>(5)?}))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn node_health_latest(&self, node: &str) -> Result<Option<serde_json::Value>> {
        Ok(self
            .conn
            .query_row(
                "SELECT observed_at,uptime_s,heap_free,heap_min,heap_max_block,heap_frag_pct,reset_reason,queue_fill_pct,drops_overflow,drops_budget,drops_expired,missed_schedules,loop_lag_max_ms,reconnects,tx_bytes,tx_frames,fw_version
                 FROM node_health WHERE node_id=?1 ORDER BY observed_at DESC LIMIT 1",
                [node],
                |r| {
                    Ok(serde_json::json!({"at": r.get::<_, i64>(0)?, "uptime_s": r.get::<_, i64>(1)?, "heap_free": r.get::<_, i64>(2)?,
                        "heap_min": r.get::<_, i64>(3)?, "heap_max_block": r.get::<_, i64>(4)?, "heap_frag_pct": r.get::<_, i64>(5)?,
                        "reset_reason": r.get::<_, i64>(6)?, "queue_fill_pct": r.get::<_, i64>(7)?, "drops_overflow": r.get::<_, i64>(8)?,
                        "drops_budget": r.get::<_, i64>(9)?, "drops_expired": r.get::<_, i64>(10)?, "missed_schedules": r.get::<_, i64>(11)?,
                        "loop_lag_max_ms": r.get::<_, i64>(12)?, "reconnects": r.get::<_, i64>(13)?, "tx_bytes": r.get::<_, i64>(14)?,
                        "tx_frames": r.get::<_, i64>(15)?, "fw_version": r.get::<_, String>(16)?}))
                },
            )
            .optional()?)
    }

    /// RSSI anchors per node/BSSID (measured only; interpolation happens in the UI).
    pub fn coverage(&self, since: UnixMs) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT node_id, bssid, count(*), avg(rssi_dbm), min(rssi_dbm), max(rssi_dbm), max(observed_at)
             FROM wifi_samples WHERE observed_at >= ?1 AND rssi_dbm IS NOT NULL AND bssid IS NOT NULL GROUP BY node_id, bssid",
        )?;
        let rows = st.query_map([since], |r| {
            Ok(serde_json::json!({"node": r.get::<_, String>(0)?, "bssid": r.get::<_, String>(1)?, "samples": r.get::<_, i64>(2)?,
                "mean_dbm": r.get::<_, f64>(3)?, "min_dbm": r.get::<_, i64>(4)?, "max_dbm": r.get::<_, i64>(5)?, "last_at": r.get::<_, i64>(6)?}))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn latest_scan(&self, node: &str) -> Result<Option<serde_json::Value>> {
        Ok(self
            .conn
            .query_row(
                "SELECT observed_at, scan_id, duration_ms, completeness, channel_counts, samples FROM ap_scan_samples WHERE node_id=?1 ORDER BY observed_at DESC LIMIT 1",
                [node],
                |r| {
                    Ok(serde_json::json!({"at": r.get::<_, i64>(0)?, "scan_id": r.get::<_, i64>(1)?, "duration_ms": r.get::<_, i64>(2)?,
                        "completeness": r.get::<_, String>(3)?,
                        "channel_counts": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(4)?).unwrap_or_default(),
                        "samples": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(5)?).unwrap_or_default()}))
                },
            )
            .optional()?)
    }

    /// Bounded metric series for a probe target, choosing resolution to keep at most
    /// `max_points` buckets. Gaps are preserved (no fabricated buckets).
    pub fn probe_series(&self, target: &str, vantage: Option<&str>, from: UnixMs, to: UnixMs, max_points: usize) -> Result<Vec<Series>> {
        let span_s = ((to - from).max(1000) / 1000).max(1);
        let max_points = max_points.clamp(10, 2000) as i64;
        let res: i64 = if span_s / 60 <= max_points { 60 } else { 3600 };
        let res = if res == 60 && span_s / 60 > max_points { 3600 } else { res };
        let mut st = self.conn.prepare(
            "SELECT vantage, bucket_start, samples, eligible, successes, timeouts, dns_bad, rtt_max_us, hist FROM rollups
             WHERE target_id=?1 AND (?2 IS NULL OR vantage=?2) AND resolution_s=?3 AND bucket_start >= ?4 AND bucket_start <= ?5
             ORDER BY vantage, bucket_start",
        )?;
        let base = if res == 3600 { 60 } else { res };
        let rows = st.query_map(params![target, vantage, base, from - from.rem_euclid(base * 1000), to], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<i64>>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?;
        let mut out: Vec<Series> = Vec::new();
        // Merge minute rows into the chosen resolution (histograms merge exactly).
        let mut acc: std::collections::BTreeMap<(String, i64), (i64, i64, i64, i64, i64, Option<i64>, LogHistogram)> = Default::default();
        for row in rows {
            let (v, t, samples, eligible, succ, timeouts, dns_bad, max, hist) = row?;
            let bucket = t - t.rem_euclid(res * 1000);
            let h: LogHistogram = serde_json::from_str(&hist).unwrap_or_default();
            let e = acc.entry((v, bucket)).or_insert((0, 0, 0, 0, 0, None, LogHistogram::default()));
            e.0 += samples;
            e.1 += eligible;
            e.2 += succ;
            e.3 += timeouts;
            e.4 += dns_bad;
            e.5 = match (e.5, max) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            e.6.merge(&h);
        }
        for ((v, t), (samples, eligible, _succ, timeouts, dns_bad, max, h)) in acc {
            let p = SeriesPoint {
                t,
                samples,
                eligible,
                loss_pct: (eligible > 0).then(|| timeouts as f64 * 100.0 / eligible as f64),
                p50_ms: h.quantile(0.5).map(|x| f64::from(x) / 1000.0),
                p95_ms: h.quantile(0.95).map(|x| f64::from(x) / 1000.0),
                max_ms: max.map(|x| x as f64 / 1000.0),
                dns_bad,
            };
            match out.last_mut() {
                Some(s) if s.vantage == v => s.points.push(p),
                _ => out.push(Series { target_id: target.into(), vantage: v, resolution_s: res, points: vec![p] }),
            }
        }
        Ok(out)
    }

    /// Distinct (target, vantage) pairs with data in the range.
    pub fn probe_catalog(&self, since: UnixMs) -> Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare("SELECT DISTINCT target_id, vantage FROM rollups WHERE resolution_s=60 AND bucket_start >= ?1 ORDER BY 1,2")?;
        let rows = st.query_map([since], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn location_history(&self, device: Option<&str>, from: UnixMs, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT device_id, at, room_id, state, confidence, model_revision FROM location_transitions
             WHERE (?1 IS NULL OR device_id=?1) AND at >= ?2 ORDER BY at DESC LIMIT ?3",
        )?;
        let rows = st.query_map(params![device, from, limit as i64], |r| {
            Ok(serde_json::json!({"device_id": r.get::<_, String>(0)?, "at": r.get::<_, i64>(1)?, "room_id": r.get::<_, Option<String>>(2)?,
                "state": r.get::<_, String>(3)?, "confidence": r.get::<_, f64>(4)?, "model_revision": r.get::<_, i64>(5)?}))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Purge all live and historical identity/location data for a device (consent revocation).
    pub fn purge_device(&mut self, device: &str) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut n = tx.execute("DELETE FROM ble_windows WHERE device_id=?1", [device])?;
        n += tx.execute("DELETE FROM location_transitions WHERE device_id=?1", [device])?;
        n += tx.execute("DELETE FROM location_state WHERE device_id=?1", [device])?;
        n += tx.execute("DELETE FROM calibration_sessions WHERE device_id=?1", [device])?;
        tx.commit()?;
        Ok(n)
    }

    pub fn audit(&mut self, at: UnixMs, actor: &str, action: &str, target: Option<&str>, detail: &serde_json::Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_events (at, actor, action, target, detail) VALUES (?1,?2,?3,?4,?5)",
            params![at, actor, action, target, detail.to_string()],
        )?;
        Ok(())
    }

    pub fn audit_list(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare("SELECT at, actor, action, target, detail FROM audit_events ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map([limit as i64], |r| {
            Ok(serde_json::json!({"at": r.get::<_, i64>(0)?, "actor": r.get::<_, String>(1)?, "action": r.get::<_, String>(2)?,
                "target": r.get::<_, Option<String>>(3)?, "detail": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(4)?).unwrap_or_default()}))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn save_config_revision(&mut self, at: UnixMs, actor: &str, sha256: &str, yaml: &str) -> Result<i64> {
        let tx = self.conn.transaction()?;
        let next: i64 = tx.query_row("SELECT coalesce(max(revision),0)+1 FROM config_revisions", [], |r| r.get(0))?;
        tx.execute("UPDATE config_revisions SET active=0", [])?;
        tx.execute(
            "INSERT INTO config_revisions (revision, at, actor, sha256, yaml, active) VALUES (?1,?2,?3,?4,?5,1)",
            params![next, at, actor, sha256, yaml],
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn active_config_revision(&self) -> Result<Option<(i64, String)>> {
        Ok(self
            .conn
            .query_row("SELECT revision, sha256 FROM config_revisions WHERE active=1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    pub fn counts(&self) -> Result<serde_json::Value> {
        let c = |t: &str| -> Result<i64> { Ok(self.conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))?) };
        Ok(serde_json::json!({
            "batches": c("batches")?, "probe_results": c("probe_results")?, "wifi_samples": c("wifi_samples")?,
            "lifecycle_events": c("lifecycle_events")?, "node_health": c("node_health")?, "ble_windows": c("ble_windows")?,
            "rollups": c("rollups")?, "incidents": c("incidents")?, "outbox": c("outbox")?, "dlq": c("dlq")?,
        }))
    }

    pub fn size_bytes(&self) -> Result<i64> {
        let pages: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let size: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(pages * size)
    }

    // ------------------------------------------------------------ maintenance

    /// Apply retention in bounded transactions (at most `batch` rows per table per call).
    pub fn retention(&mut self, now: UnixMs, r: &Retention, batch: usize) -> Result<RetentionReport> {
        let day = 86_400_000i64;
        let b = batch as i64;
        let mut rep = RetentionReport::default();
        rep.raw_batches = self.conn.execute(
            "DELETE FROM batches WHERE id IN (SELECT id FROM batches WHERE received_at < ?1 ORDER BY id LIMIT ?2)",
            params![now - i64::from(r.raw_days) * day, b],
        )?;
        rep.rollups = self.conn.execute(
            "DELETE FROM rollups WHERE rowid IN (SELECT rowid FROM rollups WHERE resolution_s=60 AND bucket_start < ?1 LIMIT ?2)",
            params![now - i64::from(r.rollup_minute_days) * day, b],
        )?;
        rep.rollups += self.conn.execute(
            "DELETE FROM rollups WHERE rowid IN (SELECT rowid FROM rollups WHERE resolution_s=3600 AND bucket_start < ?1 LIMIT ?2)",
            params![now - i64::from(r.rollup_hour_days) * day, b],
        )?;
        rep.incidents = self.conn.execute(
            "DELETE FROM incidents WHERE id IN (SELECT id FROM incidents WHERE status='resolved' AND resolved_at < ?1 LIMIT ?2)",
            params![now - i64::from(r.incident_days) * day, b],
        )?;
        rep.locations = self.conn.execute(
            "DELETE FROM location_transitions WHERE id IN (SELECT id FROM location_transitions WHERE at < ?1 LIMIT ?2)",
            params![now - i64::from(r.location_days) * day, b],
        )?;
        rep.outbox = self.conn.execute(
            "DELETE FROM outbox WHERE id IN (SELECT id FROM outbox WHERE status IN ('sent','suppressed','failed') AND created_at < ?1 LIMIT ?2)",
            params![now - 30 * day, b],
        )?;
        Ok(rep)
    }

    /// Compact minute rollups older than two hours into hour rollups (idempotent).
    pub fn rollup_hours(&mut self, now: UnixMs) -> Result<usize> {
        let cutoff = now - now.rem_euclid(3_600_000) - 3_600_000;
        let tx = self.conn.transaction()?;
        let done: i64 = tx
            .query_row("SELECT value FROM kv WHERE key='rollup_hour_done'", [], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut st = tx.prepare(
            "SELECT target_id, vantage, bucket_start, samples, eligible, successes, timeouts, other_failures, skipped, dns_bad, rtt_sum_us, rtt_min_us, rtt_max_us, hist
             FROM rollups WHERE resolution_s=60 AND bucket_start >= ?1 AND bucket_start < ?2",
        )?;
        type Agg = (i64, i64, i64, i64, i64, i64, i64, i64, Option<i64>, Option<i64>, LogHistogram);
        let mut agg: std::collections::BTreeMap<(String, String, i64), Agg> = Default::default();
        let rows = st.query_map(params![done, cutoff], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                [r.get::<_, i64>(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?],
                r.get::<_, Option<i64>>(11)?,
                r.get::<_, Option<i64>>(12)?,
                r.get::<_, String>(13)?,
            ))
        })?;
        for row in rows {
            let (t, v, b, n, mn, mx, h) = row?;
            let hb = b - b.rem_euclid(3_600_000);
            let e = agg.entry((t, v, hb)).or_insert((0, 0, 0, 0, 0, 0, 0, 0, None, None, LogHistogram::default()));
            e.0 += n[0];
            e.1 += n[1];
            e.2 += n[2];
            e.3 += n[3];
            e.4 += n[4];
            e.5 += n[5];
            e.6 += n[6];
            e.7 += n[7];
            e.8 = opt_min(e.8, mn);
            e.9 = opt_max(e.9, mx);
            e.10.merge(&serde_json::from_str(&h).unwrap_or_default());
        }
        drop(st);
        let n = agg.len();
        for ((t, v, hb), a) in agg {
            tx.execute(
                "INSERT INTO rollups (target_id,vantage,resolution_s,bucket_start,samples,eligible,successes,timeouts,other_failures,skipped,dns_bad,rtt_sum_us,rtt_min_us,rtt_max_us,hist)
                 VALUES (?1,?2,3600,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(target_id,vantage,resolution_s,bucket_start) DO UPDATE SET samples=excluded.samples, eligible=excluded.eligible,
                   successes=excluded.successes, timeouts=excluded.timeouts, other_failures=excluded.other_failures, skipped=excluded.skipped,
                   dns_bad=excluded.dns_bad, rtt_sum_us=excluded.rtt_sum_us, rtt_min_us=excluded.rtt_min_us, rtt_max_us=excluded.rtt_max_us, hist=excluded.hist",
                params![t, v, hb, a.0, a.1, a.2, a.3, a.4, a.5, a.6, a.7, a.8, a.9, serde_json::to_string(&a.10)?],
            )?;
        }
        tx.execute(
            "INSERT INTO kv (key,value) VALUES ('rollup_hour_done', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [cutoff.to_string()],
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// Online backup using SQLite's backup API (safe while WAL writes are in flight).
    pub fn backup_to(&self, dest: impl AsRef<Path>) -> Result<()> {
        let mut dst = Connection::open(dest)?;
        let b = rusqlite::backup::Backup::new(&self.conn, &mut dst)?;
        b.run_to_completion(256, std::time::Duration::from_millis(5), None)?;
        Ok(())
    }

    pub fn integrity_check(&self) -> Result<String> {
        Ok(self.conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

fn opt_min(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}
fn opt_max(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    }
}

fn row_outbox(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxItem> {
    Ok(OutboxItem {
        id: r.get(0)?,
        dedup_key: r.get(1)?,
        notifier: r.get(2)?,
        payload: r.get(3)?,
        attempts: r.get(4)?,
        status: r.get(5)?,
        created_at: r.get(6)?,
        last_error: r.get(7)?,
    })
}

fn enum_str<T: Serialize>(v: &T) -> Result<String> {
    match serde_json::to_value(v)? {
        serde_json::Value::String(s) => Ok(s),
        other => Ok(other.to_string()),
    }
}

fn insert_obs(tx: &Transaction<'_>, batch_id: i64, o: &Observation) -> Result<()> {
    let idx = o.prov.index;
    let at = o.time.observed_at;
    let src = &o.prov.source;
    match &o.kind {
        ObsKind::Probe(p) => {
            tx.execute(
                "INSERT INTO probe_results (batch_id,idx,vantage,observed_at,uncertainty_ms,target_id,kind,outcome,rtt_us,scan_overlap,dscp,sched_late_ms,error_code,dns_rcode,dns_answer,dns_transport,via_bssid)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    batch_id,
                    idx,
                    src,
                    at,
                    o.time.uncertainty_ms,
                    p.target_id,
                    p.kind,
                    p.outcome.as_str(),
                    p.rtt_us,
                    p.scan_overlap,
                    p.dscp,
                    p.sched_late_ms,
                    p.error_code,
                    p.dns.as_ref().map(|d| d.rcode),
                    p.dns.as_ref().map(|d| d.answer.clone()),
                    p.dns.as_ref().map(|d| d.transport.clone()),
                    p.via_bssid
                ],
            )?;
            update_rollup(tx, src, at, p)?;
        }
        ObsKind::Wifi(w) => {
            tx.execute(
                "INSERT INTO wifi_samples (batch_id,idx,node_id,observed_at,status,rssi_dbm,channel,bssid,assoc_gen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![batch_id, idx, src, at, w.status, w.rssi_dbm, w.channel, w.bssid, w.assoc_gen],
            )?;
        }
        ObsKind::ApScan(s) => {
            tx.execute(
                "INSERT INTO ap_scan_samples (batch_id,idx,node_id,observed_at,scan_id,duration_ms,completeness,channel_counts,samples) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    batch_id,
                    idx,
                    src,
                    at,
                    s.scan_id,
                    s.duration_ms,
                    s.completeness,
                    serde_json::to_string(&s.channel_counts)?,
                    serde_json::to_string(&s.samples)?
                ],
            )?;
        }
        ObsKind::Lifecycle(l) => {
            tx.execute(
                "INSERT INTO lifecycle_events (batch_id,idx,node_id,observed_at,event,reason,prior_bssid,new_bssid,duration_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![batch_id, idx, src, at, l.event, l.reason, l.prior_bssid, l.new_bssid, l.duration_ms],
            )?;
        }
        ObsKind::System(s) => {
            tx.execute(
                "INSERT INTO node_health (batch_id,idx,node_id,observed_at,uptime_s,heap_free,heap_min,heap_max_block,heap_frag_pct,reset_reason,queue_fill_pct,drops_overflow,drops_budget,drops_expired,missed_schedules,loop_lag_max_ms,reconnects,tx_bytes,tx_frames,fw_version)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![
                    batch_id,
                    idx,
                    src,
                    at,
                    s.uptime_s,
                    s.heap_free,
                    s.heap_min,
                    s.heap_max_block,
                    s.heap_frag_pct,
                    s.reset_reason,
                    s.queue_fill_pct,
                    s.drops_overflow,
                    s.drops_budget,
                    s.drops_expired,
                    s.missed_schedules,
                    s.loop_lag_max_ms,
                    s.reconnects,
                    s.tx_bytes,
                    s.tx_frames,
                    s.fw_version
                ],
            )?;
        }
        ObsKind::Ble(b) => {
            tx.execute(
                "INSERT INTO ble_windows (batch_id,idx,node_id,observed_at,device_id,window_ms,count,rssi_min,rssi_max,rssi_mean,coverage) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![batch_id, idx, src, at, b.device_id, b.window_ms, b.count, b.rssi_min, b.rssi_max, b.rssi_mean, b.coverage_permille],
            )?;
        }
        ObsKind::Sensor(s) => {
            tx.execute(
                "INSERT INTO sensor_samples (batch_id,idx,node_id,observed_at,sensor_id,kind,unit,value,quality,calibration_rev) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![batch_id, idx, src, at, s.sensor_id, s.kind, s.unit, s.value, s.quality, s.calibration_rev],
            )?;
        }
        ObsKind::Heartbeat { .. } => {}
    }
    Ok(())
}

fn update_rollup(tx: &Transaction<'_>, vantage: &str, at: UnixMs, p: &ProbeObs) -> Result<()> {
    let bucket = at - at.rem_euclid(60_000);
    let existing: Option<String> = tx
        .query_row(
            "SELECT hist FROM rollups WHERE target_id=?1 AND vantage=?2 AND resolution_s=60 AND bucket_start=?3",
            params![p.target_id, vantage, bucket],
            |r| r.get(0),
        )
        .optional()?;
    let mut h: LogHistogram = existing.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default();
    if let Some(r) = p.rtt_us {
        h.add(r);
    }
    let eligible = i64::from(p.outcome.is_eligible());
    let success = i64::from(p.outcome == Outcome::Success);
    let timeout = i64::from(p.outcome == Outcome::Timeout);
    let other = i64::from(p.outcome.is_failure() && p.outcome != Outcome::Timeout);
    let skipped = 1 - eligible;
    let dns_bad = i64::from(p.dns.as_ref().is_some_and(|d| !d.is_good()) && p.kind == "dns");
    let rtt = p.rtt_us.map(i64::from);
    tx.execute(
        "INSERT INTO rollups (target_id,vantage,resolution_s,bucket_start,samples,eligible,successes,timeouts,other_failures,skipped,dns_bad,rtt_sum_us,rtt_min_us,rtt_max_us,hist)
         VALUES (?1,?2,60,?3,1,?4,?5,?6,?7,?8,?9,?10,?11,?11,?12)
         ON CONFLICT(target_id,vantage,resolution_s,bucket_start) DO UPDATE SET
           samples=samples+1, eligible=eligible+excluded.eligible, successes=successes+excluded.successes,
           timeouts=timeouts+excluded.timeouts, other_failures=other_failures+excluded.other_failures,
           skipped=skipped+excluded.skipped, dns_bad=dns_bad+excluded.dns_bad, rtt_sum_us=rtt_sum_us+excluded.rtt_sum_us,
           rtt_min_us=CASE WHEN excluded.rtt_min_us IS NULL THEN rtt_min_us WHEN rtt_min_us IS NULL THEN excluded.rtt_min_us ELSE min(rtt_min_us, excluded.rtt_min_us) END,
           rtt_max_us=CASE WHEN excluded.rtt_max_us IS NULL THEN rtt_max_us WHEN rtt_max_us IS NULL THEN excluded.rtt_max_us ELSE max(rtt_max_us, excluded.rtt_max_us) END,
           hist=excluded.hist",
        params![p.target_id, vantage, bucket, eligible, success, timeout, other, skipped, dns_bad, rtt.unwrap_or(0), rtt, serde_json::to_string(&h)?],
    )?;
    Ok(())
}
