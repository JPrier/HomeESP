//! The pure processing engine: `apply(input) -> effects`.
//!
//! The server feeds it normalized observations and ticks with explicit timestamps and
//! performs the returned effects (persist, notify, publish). The simulator drives the
//! exact same engine with a fake clock, so scenario tests exercise production logic.

use crate::health::{liveness, TargetHealth};
use crate::incidents::{
    correlate, Incident, IncidentEvent, IncidentManager, NodeView, RadioView, RoamView, Snapshot, TargetView, CENTRAL,
};
use crate::location::{DeviceTracker, LocationEstimate, RoomGraph, RoomModel};
use crate::stats::WindowStats;
use ho_domain::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Probe ids the firmware runs before it has received any desired configuration.
pub const BUILTIN_NODE_TARGETS: [&str; 3] = ["gw-icmp", "server-icmp", "server-udp"];
/// Upper bound on tracked targets per vantage (state cannot grow with hostile input).
pub const MAX_TARGETS_PER_VANTAGE: usize = 32;

/// Inputs to the engine. Every input carries its own time.
#[derive(Debug, Clone)]
pub enum Input {
    Observations(Vec<Observation>),
    /// Broker-delivered status (birth / last will). Accelerates `stale` only.
    NodeStatus { node: String, online: bool, at: UnixMs },
    /// Whether the server's own ingestion path (MQTT session) is healthy.
    Ingestion { ok: bool, at: UnixMs },
    Tick(UnixMs),
    Maintenance { asset: String, on: bool, at: UnixMs },
    /// Consent revoked / device deleted: stop tracking and purge live state.
    RevokeDevice { device_id: String, at: UnixMs },
    /// New calibrated model activated by the operator.
    ActivateModel(RoomModel),
    Acknowledge { incident_id: String, at: UnixMs },
}

/// Effects for the IO layer.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum Effect {
    NodeLiveness { node: String, liveness: NodeLiveness, at: UnixMs },
    TargetHealth { vantage: String, target: String, health: Health, reason: String, at: UnixMs },
    Incident(IncidentEvent),
    Notify(Notification),
    Location(LocationEstimate),
    LocationPurged { device_id: String, at: UnixMs },
    /// BLE data dropped for a non-enrolled / non-consented / disabled device.
    BleDiscarded { count: u32 },
}

/// A notification request; delivered via the durable outbox with dedup key
/// `(incident_id, event, episode, recipient)`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Notification {
    pub incident_id: String,
    pub event: String,
    pub episode: u32,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    pub at: UnixMs,
    /// True when a maintenance window covers the scope: recorded, not sent.
    pub suppressed: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NodeState {
    pub last_seen: Option<UnixMs>,
    pub liveness: Option<NodeLiveness>,
    pub bssid: Option<String>,
    pub ap: Option<String>,
    pub rssi_dbm: Option<i8>,
    pub channel: Option<u8>,
    pub boot_id: Option<String>,
    pub broker_online: Option<bool>,
    pub last_system: Option<SystemObs>,
    pub last_scan_at: Option<UnixMs>,
    pub reconnects: u32,
}

#[derive(Debug, Clone)]
struct TargetEntry {
    kind: String,
    asset: Option<String>,
    critical: bool,
    health: TargetHealth,
}

#[derive(Debug, Clone, Default)]
struct RadioTrack {
    /// node -> (last complete scan time, saw this AP in that scan)
    last: BTreeMap<String, (UnixMs, bool)>,
    ever_seen_by: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSummary {
    pub vantage: String,
    pub target: String,
    pub kind: String,
    pub asset: Option<String>,
    pub critical: bool,
    pub health: Health,
    pub reason: String,
    pub since: UnixMs,
    pub stats: WindowStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSummary {
    pub id: String,
    pub liveness: NodeLiveness,
    pub state: NodeState,
    pub room: Option<String>,
}

/// Read-only view for the API/dashboard/HA.
#[derive(Debug, Clone, Serialize)]
pub struct EngineSnapshot {
    pub at: UnixMs,
    pub ingestion_ok: bool,
    pub nodes: Vec<NodeSummary>,
    pub targets: Vec<TargetSummary>,
    pub incidents: Vec<Incident>,
    pub locations: Vec<LocationEstimate>,
    pub ble_discarded: u64,
}

pub struct Engine {
    cfg: SiteConfig,
    graph: RoomGraph,
    model: RoomModel,
    nodes: BTreeMap<String, NodeState>,
    targets: BTreeMap<(String, String), TargetEntry>,
    roams: VecDeque<RoamView>,
    radios: BTreeMap<String, RadioTrack>,
    bssid_ap: BTreeMap<String, String>,
    incidents: IncidentManager,
    devices: BTreeMap<String, DeviceTracker>,
    locations: BTreeMap<String, LocationEstimate>,
    revoked: BTreeSet<String>,
    maintenance: BTreeSet<String>,
    ingestion_ok: bool,
    last_tick: Option<UnixMs>,
    last_location_step: Option<UnixMs>,
    ble_discarded: u64,
    /// Probe results dropped because their target id is not configured.
    pub unknown_targets: u64,
}

impl Engine {
    pub fn new(cfg: SiteConfig) -> Self {
        Self::with_incident_counter(cfg, 0)
    }

    pub fn with_incident_counter(cfg: SiteConfig, counter: u64) -> Self {
        let graph = RoomGraph::from_config(&cfg);
        let bssid_ap = cfg.radios.iter().map(|r| (r.bssid.to_lowercase(), r.ap.to_string())).collect();
        let nodes = cfg.nodes.iter().map(|n| (n.id.to_string(), NodeState::default())).collect();
        Self {
            cfg,
            graph,
            model: RoomModel::default(),
            nodes,
            targets: BTreeMap::new(),
            roams: VecDeque::new(),
            radios: BTreeMap::new(),
            bssid_ap,
            incidents: IncidentManager::with_counter(counter),
            devices: BTreeMap::new(),
            locations: BTreeMap::new(),
            revoked: BTreeSet::new(),
            maintenance: BTreeSet::new(),
            ingestion_ok: true,
            last_tick: None,
            last_location_step: None,
            ble_discarded: 0,
            unknown_targets: 0,
        }
    }

    pub fn config(&self) -> &SiteConfig {
        &self.cfg
    }

    /// Restore last-seen times from storage after a restart so a node that was
    /// already silent is still detected as missing (instead of `unknown` forever).
    pub fn seed_last_seen(&mut self, node: &str, at: UnixMs) {
        if let Some(n) = self.nodes.get_mut(node) {
            if n.last_seen.is_none() {
                n.last_seen = Some(at);
            }
        }
    }

    pub fn incident_counter(&self) -> u64 {
        self.incidents.counter()
    }

    /// Whether a node id is registered (unregistered nodes are rejected upstream).
    pub fn is_registered(&self, node: &str) -> bool {
        self.cfg.node(node).is_some()
    }

    pub fn apply(&mut self, input: Input) -> Vec<Effect> {
        let mut fx = Vec::new();
        match input {
            Input::Observations(obs) => {
                for o in obs {
                    self.observe(o, &mut fx);
                }
            }
            Input::NodeStatus { node, online, at } => {
                if let Some(n) = self.nodes.get_mut(&node) {
                    n.broker_online = Some(online);
                    if !online && n.liveness == Some(NodeLiveness::Online) {
                        n.liveness = Some(NodeLiveness::Stale);
                        fx.push(Effect::NodeLiveness { node, liveness: NodeLiveness::Stale, at });
                    }
                }
            }
            Input::Ingestion { ok, at } => {
                self.ingestion_ok = ok;
                self.tick(at, &mut fx);
            }
            Input::Tick(now) => self.tick(now, &mut fx),
            Input::Maintenance { asset, on, at } => {
                if on {
                    self.maintenance.insert(asset.clone());
                } else {
                    self.maintenance.remove(&asset);
                }
                for t in self.targets.values_mut().filter(|t| t.asset.as_deref() == Some(asset.as_str())) {
                    t.health.set_maintenance(on, at);
                }
            }
            Input::RevokeDevice { device_id, at } => {
                self.revoked.insert(device_id.clone());
                self.devices.remove(&device_id);
                self.locations.remove(&device_id);
                fx.push(Effect::LocationPurged { device_id, at });
            }
            Input::ActivateModel(m) => self.model = m,
            Input::Acknowledge { incident_id, .. } => {
                for inc in self.incidents.incidents.values_mut() {
                    if inc.id == incident_id {
                        inc.acknowledged = true;
                    }
                }
            }
        }
        fx
    }

    /// Metadata for a configured target, or `None` if the id is not allowed for this
    /// vantage (unknown ids are dropped so node input cannot grow server state).
    fn target_meta(&self, vantage: &str, target: &str, kind: &str) -> Option<(String, Option<String>, bool)> {
        if vantage == CENTRAL {
            let c = self.cfg.central_checks.iter().find(|c| c.id.as_str() == target)?;
            return Some((kind.to_string(), c.asset.as_ref().map(ToString::to_string), c.critical));
        }
        if let Some(t) = self.cfg.probe_targets.iter().find(|t| t.id.as_str() == target) {
            if !t.nodes.is_empty() && !t.nodes.iter().any(|n| n.as_str() == vantage) {
                return None;
            }
            return Some((kind.to_string(), t.asset.as_ref().map(ToString::to_string), t.critical));
        }
        BUILTIN_NODE_TARGETS.contains(&target).then(|| (kind.to_string(), None, false))
    }

    fn ap_of(&self, bssid: &str) -> Option<String> {
        self.bssid_ap.get(&bssid.to_lowercase()).cloned()
    }

    fn observe(&mut self, o: Observation, fx: &mut Vec<Effect>) {
        let src = o.prov.source.clone();
        let t = o.time.observed_at;
        if src != CENTRAL {
            let expected_ap = self.cfg.node(&src).and_then(|n| n.expected_ap.as_ref().map(ToString::to_string));
            let Some(n) = self.nodes.get_mut(&src) else { return };
            n.last_seen = Some(n.last_seen.map_or(o.time.received_at, |l| l.max(o.time.received_at)));
            if n.boot_id.as_deref() != Some(o.prov.boot_id.as_str()) {
                n.boot_id = Some(o.prov.boot_id.clone());
            }
            if n.ap.is_none() {
                n.ap = expected_ap;
            }
            if n.liveness != Some(NodeLiveness::Online) && self.ingestion_ok {
                n.liveness = Some(NodeLiveness::Online);
                fx.push(Effect::NodeLiveness { node: src.clone(), liveness: NodeLiveness::Online, at: o.time.received_at });
            }
        }
        match o.kind {
            ObsKind::Probe(p) => {
                let Some((kind, asset, critical)) = self.target_meta(&src, &p.target_id, &p.kind) else {
                    self.unknown_targets += 1;
                    return;
                };
                let key = (src.clone(), p.target_id.clone());
                if !self.targets.contains_key(&key)
                    && self.targets.keys().filter(|(v, _)| *v == src).count() >= MAX_TARGETS_PER_VANTAGE
                {
                    self.unknown_targets += 1;
                    return;
                }
                let window = self.cfg.thresholds.loss_window_ms;
                let is_dns = kind == "dns";
                let e = self.targets.entry(key).or_insert_with(|| TargetEntry {
                    kind,
                    asset: asset.clone(),
                    critical,
                    health: TargetHealth::new(window, is_dns),
                });
                if asset.as_ref().is_some_and(|a| self.maintenance.contains(a)) && e.health.health != Health::Maintenance {
                    e.health.set_maintenance(true, t);
                }
                let dns_good = p.dns.as_ref().map(DnsInfo::is_good).filter(|_| is_dns);
                if let Some(ch) = e.health.record(t, p.outcome, p.rtt_us, dns_good, p.scan_overlap, &self.cfg.thresholds) {
                    fx.push(Effect::TargetHealth { vantage: src, target: p.target_id, health: ch.to, reason: ch.reason, at: t });
                }
            }
            ObsKind::Wifi(w) => {
                let new_ap = w.bssid.as_deref().and_then(|b| self.ap_of(b));
                if let Some(n) = self.nodes.get_mut(&src) {
                    if let (Some(prev_ap), Some(next_ap)) = (n.ap.clone(), new_ap.clone()) {
                        if prev_ap != next_ap {
                            self.roams.push_back(RoamView { node: src.clone(), from_ap: prev_ap, to_ap: Some(next_ap), at: t });
                        }
                    }
                    n.bssid = w.bssid.clone().or(n.bssid.take());
                    if new_ap.is_some() {
                        n.ap = new_ap;
                    }
                    n.rssi_dbm = w.rssi_dbm;
                    n.channel = Some(w.channel);
                }
            }
            ObsKind::Lifecycle(l) => {
                if l.event == "bssid_changed" {
                    let from = l.prior_bssid.as_deref().and_then(|b| self.ap_of(b));
                    let to = l.new_bssid.as_deref().and_then(|b| self.ap_of(b));
                    if let Some(from) = from {
                        if to.as_ref() != Some(&from) {
                            self.roams.push_back(RoamView { node: src.clone(), from_ap: from, to_ap: to.clone(), at: t });
                            if let Some(n) = self.nodes.get_mut(&src) {
                                n.ap = to.or(n.ap.take());
                            }
                        }
                    }
                }
                if l.event == "mqtt_connected" {
                    if let Some(n) = self.nodes.get_mut(&src) {
                        n.reconnects += 1;
                    }
                }
            }
            ObsKind::ApScan(s) => {
                if s.completeness != "complete" {
                    return; // partial/skipped scans are not evidence of absence
                }
                if let Some(n) = self.nodes.get_mut(&src) {
                    n.last_scan_at = Some(t);
                }
                let seen_aps: BTreeSet<String> = s.samples.iter().filter_map(|x| self.ap_of(&x.bssid)).collect();
                let aps: BTreeSet<String> = self.bssid_ap.values().cloned().collect();
                for ap in aps {
                    let tr = self.radios.entry(ap.clone()).or_default();
                    let saw = seen_aps.contains(&ap);
                    tr.last.insert(src.clone(), (t, saw));
                    if saw {
                        tr.ever_seen_by.insert(src.clone());
                    }
                }
            }
            ObsKind::System(s) => {
                if let Some(n) = self.nodes.get_mut(&src) {
                    n.last_system = Some(s);
                }
            }
            ObsKind::Ble(b) => self.observe_ble(&src, t, &b, fx),
            ObsKind::Heartbeat { .. } | ObsKind::Sensor(_) => {}
        }
    }

    fn observe_ble(&mut self, node: &str, t: UnixMs, b: &BleObs, fx: &mut Vec<Effect>) {
        let enrolled = self.cfg.devices.iter().find(|d| d.id.as_str() == b.device_id);
        let allowed = self.cfg.privacy.location_enabled
            && enrolled.is_some_and(|d| d.consent)
            && !self.revoked.contains(&b.device_id);
        if !allowed {
            // No collection while disabled / without consent / after revocation.
            self.ble_discarded += 1;
            fx.push(Effect::BleDiscarded { count: 1 });
            return;
        }
        let th = self.cfg.thresholds.location.clone();
        let tr = self.devices.entry(b.device_id.clone()).or_insert_with(|| DeviceTracker::new(&b.device_id));
        tr.observe(node, t, b.rssi_mean, f64::from(b.coverage_permille) / 1000.0, &th);
    }

    fn tick(&mut self, now: UnixMs, fx: &mut Vec<Effect>) {
        self.last_tick = Some(now);
        let th = self.cfg.thresholds.clone();
        // 1. Liveness.
        for (id, n) in self.nodes.iter_mut() {
            let l = liveness(n.last_seen, now, th.node_missing_ms, self.ingestion_ok);
            if n.liveness != Some(l) && !(n.liveness.is_none() && l == NodeLiveness::Unknown) {
                n.liveness = Some(l);
                fx.push(Effect::NodeLiveness { node: id.clone(), liveness: l, at: now });
            }
        }
        // 2. Target staleness / recovery timers.
        for ((v, t), e) in self.targets.iter_mut() {
            if let Some(ch) = e.health.evaluate(now, &th) {
                fx.push(Effect::TargetHealth { vantage: v.clone(), target: t.clone(), health: ch.to, reason: ch.reason, at: now });
            }
        }
        // 3. Correlate.
        let horizon = th.correlation_window_ms * 5;
        while self.roams.front().is_some_and(|r| now - r.at > horizon) {
            self.roams.pop_front();
        }
        let nodes: Vec<NodeView> = self
            .nodes
            .iter()
            .map(|(id, n)| NodeView { id: id.clone(), liveness: n.liveness.unwrap_or(NodeLiveness::Unknown), ap: n.ap.clone() })
            .collect();
        let targets: Vec<TargetView> = self
            .targets
            .iter()
            .map(|((v, t), e)| TargetView {
                vantage: v.clone(),
                target_id: t.clone(),
                kind: e.kind.clone(),
                asset: e.asset.clone(),
                critical: e.critical,
                health: e.health.health,
                reason: e.health.reason.clone(),
            })
            .collect();
        let radio_recent = 300_000;
        let radios: Vec<RadioView> = self
            .radios
            .iter()
            .map(|(ap, tr)| {
                let mut rv = RadioView { ap: ap.clone(), ..Default::default() };
                for (node, (t, saw)) in &tr.last {
                    if now - t > radio_recent {
                        continue;
                    }
                    if *saw {
                        rv.seen_by.insert(node.clone());
                    } else if tr.ever_seen_by.contains(node) {
                        rv.absent_for.insert(node.clone());
                    }
                }
                rv
            })
            .collect();
        let roams: Vec<RoamView> = self.roams.iter().cloned().collect();
        let hyps = correlate(&Snapshot {
            config: &self.cfg,
            now,
            ingestion_ok: self.ingestion_ok,
            nodes: &nodes,
            targets: &targets,
            roams: &roams,
            radios: &radios,
        });
        for ev in self.incidents.reconcile(hyps, now, &th) {
            if ev.kind.notifies() {
                let inc = self.incidents.incidents.get(&ev.key);
                let suppressed = inc.is_some_and(|i| i.hypothesis.scope_assets.iter().any(|a| self.maintenance.contains(a)));
                fx.push(Effect::Notify(Notification {
                    incident_id: ev.incident_id.clone(),
                    event: ev.kind.as_str().into(),
                    episode: ev.episode,
                    severity: ev.severity,
                    title: ev.title.clone(),
                    body: inc.map(|i| render_body(i, &ev)).unwrap_or_default(),
                    at: now,
                    suppressed,
                }));
            }
            fx.push(Effect::Incident(ev));
        }
        // 4. Location windows.
        let win = th.location.window_ms;
        if self.last_location_step.is_none_or(|l| now - l >= win) {
            self.last_location_step = Some(now);
            let scanning: BTreeSet<String> = self
                .nodes
                .iter()
                .filter(|(_, n)| n.liveness == Some(NodeLiveness::Online))
                .map(|(id, _)| id.clone())
                .collect();
            for (id, tr) in self.devices.iter_mut() {
                let est = tr.step(now, &self.model, &self.graph, &th.location, &scanning);
                self.locations.insert(id.clone(), est.clone());
                if let Some(e) = tr.changed(est) {
                    fx.push(Effect::Location(e));
                }
            }
        }
    }

    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            at: self.last_tick.unwrap_or(0),
            ingestion_ok: self.ingestion_ok,
            nodes: self
                .nodes
                .iter()
                .map(|(id, n)| NodeSummary {
                    id: id.clone(),
                    liveness: n.liveness.unwrap_or(NodeLiveness::Unknown),
                    state: n.clone(),
                    room: self.cfg.node(id).and_then(|c| c.room.as_ref().map(ToString::to_string)),
                })
                .collect(),
            targets: self
                .targets
                .iter()
                .map(|((v, t), e)| TargetSummary {
                    vantage: v.clone(),
                    target: t.clone(),
                    kind: e.kind.clone(),
                    asset: e.asset.clone(),
                    critical: e.critical,
                    health: e.health.health,
                    reason: e.health.reason.clone(),
                    since: e.health.since,
                    stats: e.health.stats(),
                })
                .collect(),
            incidents: self.incidents.incidents.values().cloned().collect(),
            locations: self.locations.values().cloned().collect(),
            ble_discarded: self.ble_discarded,
        }
    }

    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.incidents.active().collect()
    }
}

/// Render a human notification body in the spec's style (§14.2).
pub fn render_body(i: &Incident, ev: &IncidentEvent) -> String {
    let h = &i.hypothesis;
    let mut s = String::new();
    let sev = match i.severity {
        Severity::Critical => "CRITICAL",
        Severity::Warning => "WARNING",
        Severity::Info => "INFO",
    };
    s.push_str(&format!("{sev} [{}] {}\n", ev.kind.as_str(), h.title));
    if !h.affected_nodes.is_empty() {
        s.push_str(&format!("Impact: {} node(s): {}\n", h.affected_nodes.len(), h.affected_nodes.join(", ")));
    }
    s.push_str(&format!("Hypothesis: {} (confidence: {:?})\n", h.cause, h.confidence));
    for e in h.evidence.iter().take(4) {
        s.push_str(&format!("Evidence: {e}\n"));
    }
    for c in h.contradicting.iter().take(2) {
        s.push_str(&format!("Counter-evidence: {c}\n"));
    }
    s.push_str(&format!("Next check: {}\n", h.next_check));
    s.push_str(&format!("Incident {} episode {}", i.id, ev.episode));
    s
}
