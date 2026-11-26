//! Dedicated blocking writer thread owning the read-write SQLite connection.
//! Every durable mutation goes through here, in order.

use ho_domain::{Observation, Retention, UnixMs};
use ho_logic::incidents::{Incident, IncidentEvent};
use ho_logic::location::LocationEstimate;
use ho_storage::{BatchMeta, InsertOutcome, RetentionReport, Store};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

pub type OutboxRow = (String, String, String, UnixMs, bool);

pub enum WriteCmd {
    Frame { meta: BatchMeta, obs: Vec<Observation>, reply: oneshot::Sender<Result<InsertOutcome, String>> },
    Derived { incidents: Vec<Incident>, events: Vec<IncidentEvent>, outbox: Vec<OutboxRow>, locations: Vec<LocationEstimate>, checkpoint: Option<(String, String)> },
    Capabilities { node: String, at: UnixMs, chip: String, fw: String, profile: String, features: u32, flash_kb: u32, json: String },
    ConfigStatus { node: String, revision: u64, state: String, reason: u8 },
    Desired { node: String, revision: u64 },
    Dlq { at: UnixMs, node: Option<String>, topic: String, reason: String, head: Vec<u8> },
    Audit { at: UnixMs, actor: String, action: String, target: Option<String>, detail: serde_json::Value },
    OutboxAttempt { id: i64, now: UnixMs, ok: bool, error: Option<String>, retry_at: Option<UnixMs> },
    Purge { device: String, reply: oneshot::Sender<Result<usize, String>> },
    Note { id: String, at: UnixMs, actor: String, note: String, reply: oneshot::Sender<Result<bool, String>> },
    Ack { id: String, reply: oneshot::Sender<Result<bool, String>> },
    Retention { now: UnixMs, r: Retention, reply: oneshot::Sender<Result<RetentionReport, String>> },
    RollupHours { now: UnixMs },
    Backup { path: PathBuf, reply: oneshot::Sender<Result<(), String>> },
    KvSet { key: String, value: String },
    SaveConfigRevision { at: UnixMs, actor: String, sha: String, yaml: String, reply: oneshot::Sender<Result<i64, String>> },
}

#[derive(Clone)]
pub struct WriterHandle {
    tx: mpsc::Sender<WriteCmd>,
}

impl WriterHandle {
    /// Queue a command, waiting for capacity (backpressure to the caller).
    pub async fn send(&self, cmd: WriteCmd) -> Result<(), String> {
        self.tx.send(cmd).await.map_err(|_| "writer stopped".to_string())
    }
    /// Queue without waiting; `false` if the queue is full (caller sheds/counts).
    pub fn try_send(&self, cmd: WriteCmd) -> bool {
        self.tx.try_send(cmd).is_ok()
    }
    pub fn capacity(&self) -> usize {
        self.tx.capacity()
    }
    pub fn max_capacity(&self) -> usize {
        self.tx.max_capacity()
    }

    pub async fn insert_frame(&self, meta: BatchMeta, obs: Vec<Observation>) -> Result<InsertOutcome, String> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteCmd::Frame { meta, obs, reply }).await?;
        rx.await.map_err(|_| "writer dropped reply".to_string())?
    }

    pub async fn call<T>(&self, mk: impl FnOnce(oneshot::Sender<Result<T, String>>) -> WriteCmd) -> Result<T, String> {
        let (reply, rx) = oneshot::channel();
        self.send(mk(reply)).await?;
        rx.await.map_err(|_| "writer dropped reply".to_string())?
    }
}

/// Spawn the writer thread. Returns its handle; the thread exits when all handles drop.
pub fn spawn(mut store: Store, queue: usize) -> WriterHandle {
    let (tx, mut rx) = mpsc::channel::<WriteCmd>(queue.max(16));
    let spawned = std::thread::Builder::new().name("db-writer".into()).spawn(move || {
        while let Some(cmd) = rx.blocking_recv() {
            apply(&mut store, cmd);
        }
        if let Err(e) = store.checkpoint() {
            tracing::warn!(error = %e, "final checkpoint failed");
        }
        tracing::info!("writer thread stopped");
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "failed to spawn writer thread");
    }
    WriterHandle { tx }
}

fn apply(s: &mut Store, cmd: WriteCmd) {
    let log = |what: &str, r: Result<(), ho_storage::StoreError>| {
        if let Err(e) = r {
            tracing::error!(error = %e, op = what, "database write failed");
        }
    };
    match cmd {
        WriteCmd::Frame { meta, obs, reply } => {
            let _ = reply.send(s.insert_frame(&meta, &obs).map_err(|e| e.to_string()));
        }
        WriteCmd::Derived { incidents, events, outbox, locations, checkpoint } => {
            let cp = checkpoint.as_ref().map(|(k, v)| (k.as_str(), v.as_str()));
            log("derived", s.commit_derived(&incidents, &events, &outbox, &locations, cp));
        }
        WriteCmd::Capabilities { node, at, chip, fw, profile, features, flash_kb, json } => {
            log("capabilities", s.upsert_capabilities(&node, at, &chip, &fw, &profile, features, flash_kb, &json))
        }
        WriteCmd::ConfigStatus { node, revision, state, reason } => log("config_status", s.set_config_status(&node, revision, &state, reason)),
        WriteCmd::Desired { node, revision } => log("desired", s.set_desired_revision(&node, revision)),
        WriteCmd::Dlq { at, node, topic, reason, head } => log("dlq", s.record_dlq(at, node.as_deref(), &topic, &reason, &head)),
        WriteCmd::Audit { at, actor, action, target, detail } => log("audit", s.audit(at, &actor, &action, target.as_deref(), &detail)),
        WriteCmd::OutboxAttempt { id, now, ok, error, retry_at } => log("outbox", s.outbox_attempt(id, now, ok, error.as_deref(), retry_at)),
        WriteCmd::Purge { device, reply } => {
            let _ = reply.send(s.purge_device(&device).map_err(|e| e.to_string()));
        }
        WriteCmd::Note { id, at, actor, note, reply } => {
            let _ = reply.send(s.add_incident_note(&id, at, &actor, &note).map_err(|e| e.to_string()));
        }
        WriteCmd::Ack { id, reply } => {
            let _ = reply.send(s.acknowledge_incident(&id).map_err(|e| e.to_string()));
        }
        WriteCmd::Retention { now, r, reply } => {
            let _ = reply.send(s.retention(now, &r, 5000).map_err(|e| e.to_string()));
        }
        WriteCmd::RollupHours { now } => {
            if let Err(e) = s.rollup_hours(now) {
                tracing::warn!(error = %e, "hour rollup failed");
            }
        }
        WriteCmd::Backup { path, reply } => {
            let _ = reply.send(s.backup_to(&path).map_err(|e| e.to_string()));
        }
        WriteCmd::KvSet { key, value } => log("kv", s.kv_set(&key, &value)),
        WriteCmd::SaveConfigRevision { at, actor, sha, yaml, reply } => {
            let _ = reply.send(s.save_config_revision(at, &actor, &sha, &yaml).map_err(|e| e.to_string()));
        }
    }
}
