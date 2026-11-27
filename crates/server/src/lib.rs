//! Home Observatory central service: composition of ingestion, storage, the pure
//! engine, collectors, integrations and the HTTP API.

pub mod api;
pub mod auth;
pub mod desired;
pub mod effects;
pub mod ingest;
pub mod jobs;
pub mod writer;

use ho_domain::{SiteConfig, UnixMs};
use ho_logic::engine::{Engine, EngineSnapshot};

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

/// Wall clock (the only place the service reads time; logic receives it explicitly).
pub fn now_ms() -> UnixMs {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Low-cardinality counters for `/metrics` and the status page.
#[derive(Default)]
pub struct Metrics {
    pub frames_accepted: AtomicU64,
    pub frames_duplicate: AtomicU64,
    pub frames_shed: AtomicU64,
    pub bytes_in: AtomicU64,
    pub acks_sent: AtomicU64,
    pub observations: AtomicU64,
    pub notifications_sent: AtomicU64,
    pub notifications_failed: AtomicU64,
    pub ingest_lag_ms_last: AtomicU64,
    pub ingest_lag_ms_max: AtomicU64,
    pub process_us_last: AtomicU64,
    pub rejected: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    pub fn reject(&self, reason: &str) {
        if let Ok(mut m) = self.rejected.lock() {
            *m.entry(reason.to_string()).or_default() += 1;
        }
    }
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Everything the tasks and handlers share.
pub struct Shared {
    pub cfg: SiteConfig,
    pub config_path: Option<PathBuf>,
    pub db_path: PathBuf,
    pub engine: Mutex<Engine>,
    pub snapshot: RwLock<Arc<EngineSnapshot>>,
    pub writer: writer::WriterHandle,
    pub metrics: Metrics,
    pub events: broadcast::Sender<String>,
    pub tokens: auth::Tokens,
    pub mqtt: RwLock<Option<rumqttc::AsyncClient>>,
    pub mqtt_connected: AtomicBool,
    pub started_at: UnixMs,
    pub desired_revision: AtomicU64,
    pub server_seq: AtomicU64,
    pub echo_stats: Arc<Mutex<(u64, u64)>>,
    pub ingest: Mutex<ingest::IngestState>,
    pub dashboard_dir: Option<PathBuf>,
    pub notifier_tokens: BTreeMap<String, String>,
    pub watchdog_ok: Mutex<Option<(UnixMs, bool)>>,
}

impl Shared {
    pub fn snapshot(&self) -> Arc<EngineSnapshot> {
        self.snapshot
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }

    /// Apply an engine input without holding the lock across any await point.
    pub fn apply(&self, input: ho_logic::engine::Input) -> Vec<ho_logic::engine::Effect> {
        match self.engine.lock() {
            Ok(mut e) => e.apply(input),
            Err(p) => p.into_inner().apply(input),
        }
    }

    /// Run a closure against the engine (lock released before returning).
    pub fn with_engine<T>(&self, f: impl FnOnce(&mut Engine) -> T) -> T {
        match self.engine.lock() {
            Ok(mut e) => f(&mut e),
            Err(p) => f(&mut p.into_inner()),
        }
    }

    pub fn next_server_seq(&self) -> u64 {
        self.server_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn mqtt_client(&self) -> Option<rumqttc::AsyncClient> {
        self.mqtt.read().ok().and_then(|g| g.clone())
    }

    /// Open a read-only store for query workloads (separate from the writer).
    pub fn reader(&self) -> Result<ho_storage::Store, String> {
        ho_storage::Store::open_readonly(&self.db_path).map_err(|e| e.to_string())
    }
}

pub type App = Arc<Shared>;
