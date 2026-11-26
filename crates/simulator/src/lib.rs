//! Deterministic simulator: a seeded world of nodes, APs, resolver, WAN and moving
//! BLE devices that emits *authentic protocol frames* (encoded with `ho-protocol`) and
//! central observations. Frames are pushed through the same decode -> validate ->
//! sequence/clock -> normalize -> engine path as the server's ingestion, so scenario
//! tests exercise production logic. Never touches a real network.

pub mod scenarios;

use ho_domain::*;
use ho_logic::engine::{Effect, Engine, Input};
use ho_logic::incidents::{Incident, IncidentStatus};
use ho_logic::location::{calibrate, LabeledSample, RoomModel};
use ho_logic::normalize::{normalize, FrameCtx};
use ho_logic::seq::{SeqTracker, SeqVerdict};
use ho_logic::timesync::OffsetEstimator;
use ho_protocol as p;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SIM_CONFIG: &str = include_str!("../../../configs/sim-site.yaml");

/// Base wall-clock for simulations (2026-01-01T00:00:00Z).
pub const T0: UnixMs = 1_767_225_600_000;

pub fn sim_config() -> SiteConfig {
    match SiteConfig::from_yaml_str(SIM_CONFIG) {
        Ok(c) => c,
        Err(e) => unreachable_config(&e.to_string()),
    }
}

#[allow(clippy::panic)]
fn unreachable_config(e: &str) -> ! {
    panic!("embedded simulation config is invalid: {e}")
}

/// A recorded frame for JSONL export / replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Recorded {
    pub received_at: UnixMs,
    pub topic: String,
    pub hex: String,
}

#[derive(Debug, Clone)]
pub struct SimNode {
    pub id: String,
    pub pos: [f64; 2],
    pub boot: [u8; 16],
    pub seq: u64,
    /// Node monotonic clock = (server time - boot time) * (1 + drift).
    pub boot_at: UnixMs,
    pub drift_ppm: f64,
    pub online: bool,
    pub ap: String,
    pub bssid: [u8; 6],
    pub assoc_gen: u16,
    pub next_report: UnixMs,
    pub next_scan: UnixMs,
    pub probe_phase: UnixMs,
    pub pending_life: Vec<(p::LifecycleEvent, u16, Option<[u8; 6]>, Option<[u8; 6]>)>,
    /// Frames buffered while the broker/network is unreachable (bounded).
    pub offline_buffer: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SimDevice {
    pub id: String,
    /// Where the device physically is (None = away / out of range).
    pub pos: Option<[f64; 2]>,
    pub room: Option<String>,
    pub advertising: bool,
}

/// Network conditions the scenario controls.
#[derive(Debug, Clone, Default)]
pub struct NetState {
    pub ap_down: Option<String>,
    pub ap_radio_down: Option<String>,
    pub dns_down: bool,
    pub dns_wireless_drop: bool,
    pub wan_down: bool,
    pub wireless_congested: bool,
    pub wired_congested: bool,
    pub app_down: bool,
    pub broker_down: bool,
    /// Extra ms added to wireless RTT.
    pub extra_wireless_ms: f64,
}

pub struct Harness {
    pub cfg: SiteConfig,
    pub engine: Engine,
    clocks: BTreeMap<String, OffsetEstimator>,
    seqs: BTreeMap<String, SeqTracker>,
    bssids: BTreeMap<String, String>,
    pub rejected: BTreeMap<String, u64>,
    pub duplicates: u64,
    pub accepted: u64,
    /// Mirrors the database unique key (site, node, boot, sequence).
    durable: std::collections::BTreeSet<(String, [u8; 16], u64)>,
    pub effects: Vec<(UnixMs, Effect)>,
    pub recorded: Vec<Recorded>,
    pub record: bool,
}

impl Harness {
    pub fn new(cfg: SiteConfig) -> Self {
        Self {
            engine: Engine::new(cfg.clone()),
            cfg,
            clocks: BTreeMap::new(),
            seqs: BTreeMap::new(),
            bssids: BTreeMap::new(),
            rejected: BTreeMap::new(),
            duplicates: 0,
            accepted: 0,
            durable: Default::default(),
            effects: Vec::new(),
            recorded: Vec::new(),
            record: false,
        }
    }

    fn reject(&mut self, why: &str) {
        *self.rejected.entry(why.to_string()).or_default() += 1;
    }

    /// Server-equivalent ingestion of one MQTT message.
    pub fn ingest(&mut self, topic: &str, payload: &[u8], received_at: UnixMs) {
        if self.record {
            self.recorded.push(Recorded { received_at, topic: topic.into(), hex: hex_encode(payload) });
        }
        let prefix = self.cfg.topic_prefix();
        let Some(rest) = topic.strip_prefix(&prefix).and_then(|r| r.strip_prefix("/nodes/")) else { return self.reject("bad_topic") };
        let Some((node, _suffix)) = rest.split_once('/') else { return self.reject("bad_topic") };
        if self.cfg.node(node).is_none() {
            return self.reject("unregistered_node");
        }
        if payload.len() > p::MAX_FRAME_BYTES {
            return self.reject("too_large");
        }
        let frame = match p::decode_frame(payload) {
            Ok(f) => f,
            Err(e) => return self.reject(e.label()),
        };
        if frame.header.node_id != node {
            return self.reject("envelope_topic_mismatch");
        }
        let h = frame.header;
        let clock = self.clocks.entry(node.to_string()).or_default();
        clock.observe(h.boot_id, h.sent_mono_ms, received_at);
        let verdict = self.seqs.entry(node.to_string()).or_default().observe(h.boot_id, h.sequence);
        if verdict == SeqVerdict::Duplicate || !self.durable.insert((node.to_string(), h.boot_id, h.sequence)) {
            self.duplicates += 1;
            return;
        }
        let ctx = FrameCtx { received_at, clock, current_bssid: self.bssids.get(node).cloned() };
        let obs = normalize(&frame, &ctx);
        for o in &obs {
            if let ObsKind::Wifi(w) = &o.kind {
                if let Some(b) = &w.bssid {
                    self.bssids.insert(node.to_string(), b.clone());
                }
            }
        }
        self.accepted += 1;
        let fx = self.engine.apply(Input::Observations(obs));
        self.effects.extend(fx.into_iter().map(|e| (received_at, e)));
    }

    pub fn central(&mut self, at: UnixMs, seq: u64, probe: ProbeObs) {
        let o = Observation {
            prov: Provenance { source: "central".into(), boot_id: "sim-central".into(), sequence: seq, index: 0 },
            time: EventTime { observed_at: at, uncertainty_ms: 1, received_at: at },
            kind: ObsKind::Probe(probe),
        };
        let fx = self.engine.apply(Input::Observations(vec![o]));
        self.effects.extend(fx.into_iter().map(|e| (at, e)));
    }

    pub fn input(&mut self, at: UnixMs, i: Input) {
        let fx = self.engine.apply(i);
        self.effects.extend(fx.into_iter().map(|e| (at, e)));
    }

    /// Incidents ever opened, in id order.
    pub fn incidents(&self) -> Vec<Incident> {
        self.engine.snapshot().incidents
    }

    pub fn active(&self) -> Vec<Incident> {
        self.incidents().into_iter().filter(|i| i.status != IncidentStatus::Resolved).collect()
    }

    pub fn notifications(&self) -> Vec<&ho_logic::engine::Notification> {
        self.effects.iter().filter_map(|(_, e)| if let Effect::Notify(n) = e { Some(n) } else { None }).collect()
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect()
}

/// The simulated world.
pub struct World {
    pub now: UnixMs,
    pub rng: ChaCha8Rng,
    pub nodes: Vec<SimNode>,
    pub devices: Vec<SimDevice>,
    pub net: NetState,
    pub h: Harness,
    central_seq: u64,
    next_central: BTreeMap<String, UnixMs>,
    next_tick: UnixMs,
    pub bytes_sent: u64,
    pub frames_sent: u64,
    pub frames_dropped_offline: u64,
}

fn bssid_of(cfg: &SiteConfig, ap: &str) -> [u8; 6] {
    cfg.radios.iter().find(|r| r.ap.as_str() == ap).and_then(|r| parse_mac(&r.bssid)).unwrap_or([2, 0, 0, 0, 0, 0])
}

fn room_center(cfg: &SiteConfig, room: &str) -> [f64; 2] {
    cfg.rooms
        .iter()
        .find(|r| r.id.as_str() == room)
        .filter(|r| !r.polygon.is_empty())
        .map(|r| {
            let n = r.polygon.len() as f64;
            [r.polygon.iter().map(|p| p[0]).sum::<f64>() / n, r.polygon.iter().map(|p| p[1]).sum::<f64>() / n]
        })
        .unwrap_or([0.0, 0.0])
}

impl World {
    pub fn new(cfg: SiteConfig, seed: u64) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let nodes = cfg
            .nodes
            .iter()
            .map(|n| {
                let ap = n.expected_ap.as_ref().map(ToString::to_string).unwrap_or_default();
                let mut boot = [0u8; 16];
                rng.fill(&mut boot);
                SimNode {
                    id: n.id.to_string(),
                    pos: n.position.map(|p| [p[0], p[1]]).unwrap_or([0.0, 0.0]),
                    boot,
                    seq: 0,
                    boot_at: T0 - rng.gen_range(10_000..100_000),
                    drift_ppm: rng.gen_range(-50.0..50.0),
                    online: true,
                    bssid: bssid_of(&cfg, &ap),
                    ap,
                    assoc_gen: 1,
                    next_report: T0 + rng.gen_range(0..2000),
                    next_scan: T0 + rng.gen_range(5_000..60_000),
                    probe_phase: rng.gen_range(0..5000),
                    pending_life: vec![],
                    offline_buffer: vec![],
                }
            })
            .collect();
        let devices = cfg
            .devices
            .iter()
            .map(|d| SimDevice { id: d.id.to_string(), pos: None, room: None, advertising: true })
            .collect();
        Self {
            now: T0,
            rng,
            nodes,
            devices,
            net: NetState::default(),
            h: Harness::new(cfg),
            central_seq: 0,
            next_central: BTreeMap::new(),
            next_tick: T0,
            bytes_sent: 0,
            frames_sent: 0,
            frames_dropped_offline: 0,
        }
    }

    pub fn cfg(&self) -> &SiteConfig {
        &self.h.cfg
    }

    fn mono(&self, n: &SimNode) -> u64 {
        let elapsed = (self.now - n.boot_at) as f64 * (1.0 + n.drift_ppm / 1e6);
        elapsed.max(0.0) as u64
    }

    /// Place a device in a room (random position near the room center) or away.
    pub fn place(&mut self, device: &str, room: Option<&str>) {
        let pos = room.map(|r| {
            let c = room_center(&self.h.cfg, r);
            [c[0] + self.rng.gen_range(-1.0..1.0), c[1] + self.rng.gen_range(-1.0..1.0)]
        });
        if let Some(d) = self.devices.iter_mut().find(|d| d.id == device) {
            d.pos = pos;
            d.room = room.map(String::from);
        }
    }

    /// Reboot a node (new boot id, sequence restarts).
    pub fn reboot(&mut self, node: &str) {
        let mut boot = [0u8; 16];
        self.rng.fill(&mut boot);
        let now = self.now;
        if let Some(n) = self.nodes.iter_mut().find(|n| n.id == node) {
            n.boot = boot;
            n.seq = 0;
            n.boot_at = now;
            n.pending_life.push((p::LifecycleEvent::Boot, 6, None, None));
        }
    }

    /// Move a node's association to another AP (roam), emitting the lifecycle event.
    pub fn roam(&mut self, node: &str, to_ap: &str) {
        let to = bssid_of(&self.h.cfg, to_ap);
        if let Some(n) = self.nodes.iter_mut().find(|n| n.id == node) {
            let from = n.bssid;
            n.ap = to_ap.into();
            n.bssid = to;
            n.assoc_gen = n.assoc_gen.wrapping_add(1);
            n.pending_life.push((p::LifecycleEvent::BssidChanged, 1, Some(from), Some(to)));
        }
    }

    fn rssi(&mut self, from: [f64; 2], to: [f64; 2], same_room: bool) -> f64 {
        let d = ((from[0] - to[0]).powi(2) + (from[1] - to[1]).powi(2)).sqrt();
        let wall = if same_room { 0.0 } else { 7.0 };
        -45.0 - 22.0 * (d + 0.5).log10() - wall + self.gauss() * 3.0
    }

    fn gauss(&mut self) -> f64 {
        // Box-Muller
        let u1: f64 = self.rng.gen_range(1e-9..1.0);
        let u2: f64 = self.rng.gen_range(0.0..1.0);
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }

    fn node_reachable(&self, n: &SimNode) -> bool {
        n.online && self.net.ap_down.as_deref() != Some(n.ap.as_str()) && self.net.ap_radio_down.as_deref() != Some(n.ap.as_str())
    }

    fn wireless_rtt(&mut self) -> Option<u32> {
        let base = 3.0 + self.rng.gen_range(0.0..3.0) + self.net.extra_wireless_ms;
        let (loss, extra) = match (self.net.wireless_congested, self.net.wired_congested) {
            (_, true) => (0.12, 60.0),
            (true, false) => (0.12, 80.0),
            _ => (0.005, 0.0),
        };
        if self.rng.gen_bool(loss) {
            return None;
        }
        Some(((base + extra * self.rng.gen_range(0.5..1.5)) * 1000.0) as u32)
    }

    fn node_frame(&mut self, idx: usize) -> Option<(String, Vec<u8>)> {
        let now = self.now;
        let mono = { let n = &self.nodes[idx]; self.mono(n) };
        let devices = self.devices.clone();
        let cfg_loc = self.h.cfg.privacy.location_enabled;
        let net = self.net.clone();
        let rtt_gw = self.wireless_rtt();
        let rtt_srv = self.wireless_rtt();
        let rtt_echo = self.wireless_rtt();
        let rtt_dns = self.wireless_rtt(); // independent loss draw per probe
        let n_pos = self.nodes[idx].pos;
        let node_room = self.h.cfg.node(&self.nodes[idx].id).and_then(|c| c.room.as_ref().map(ToString::to_string));
        // BLE summaries for advertising devices in range.
        let mut ble: Vec<(String, i8, i8, i32, u16)> = Vec::new();
        for d in devices.iter().filter(|d| d.advertising) {
            let Some(pos) = d.pos else { continue };
            let same = d.room.is_some() && d.room == node_room;
            let mut samples = Vec::new();
            for _ in 0..4 {
                if self.rng.gen_bool(0.85) {
                    samples.push(self.rssi(n_pos, pos, same));
                }
            }
            samples.retain(|r| *r > -98.0);
            if samples.is_empty() {
                continue;
            }
            let mn = samples.iter().cloned().fold(f64::MAX, f64::min) as i8;
            let mx = samples.iter().cloned().fold(f64::MIN, f64::max) as i8;
            let sum: i32 = samples.iter().map(|x| *x as i32).sum();
            ble.push((d.id.clone(), mn, mx, sum, samples.len() as u16));
        }
        let n = &mut self.nodes[idx];
        n.seq += 1;
        let seq = n.seq;
        let node_id = n.id.clone();
        let header = p::Header {
            kind: p::MsgKind::Telemetry,
            flags: 0,
            node_id: &node_id,
            boot_id: n.boot,
            sequence: seq,
            sent_mono_ms: mono,
            config_revision: 1,
        };
        let mut buf = [0u8; p::MAX_FRAME_BYTES];
        let mut w = p::FrameWriter::new(&mut buf, &header, p::MAX_FRAME_BYTES).ok()?;
        let _ = w.push(&p::Record::WifiLink(p::WifiLink {
            age_ms: 10,
            status: p::LinkStatus::Connected,
            rssi_dbm: Some(-60),
            channel: 1,
            bssid: Some(n.bssid),
            assoc_gen: n.assoc_gen,
        }));
        let probe = |id: &'static str, kind, rtt: Option<u32>, dns: Option<p::DnsDetail>| {
            p::Record::Probe(p::Probe {
                age_ms: 500,
                target_id: id,
                kind,
                outcome: if rtt.is_some() { p::ProbeOutcome::Success } else { p::ProbeOutcome::Timeout },
                rtt_us: rtt,
                scan_overlap: false,
                dscp: 0,
                sched_late_ms: 0,
                error_code: if rtt.is_some() { 0 } else { -1 },
                dns,
            })
        };
        // Probes run every report for simplicity (cadence shaping is firmware-tested).
        let _ = w.push(&probe("gw-icmp", p::ProbeKind::Icmp, rtt_gw, None));
        let _ = w.push(&probe("server-icmp", p::ProbeKind::Icmp, rtt_srv, None));
        let _ = w.push(&probe("server-udp", p::ProbeKind::UdpEcho, rtt_echo, None));
        let dns_ok = !net.dns_down && !(net.dns_wireless_drop) && rtt_dns.is_some();
        let dns_rtt = if dns_ok { rtt_dns.map(|r| r + 1500) } else { None };
        let _ = w.push(&probe(
            "dns-local",
            p::ProbeKind::Dns,
            dns_rtt,
            Some(p::DnsDetail {
                rcode: if net.dns_down { 2 } else { 0 },
                answer: if dns_ok { p::DnsAnswer::Match } else if net.dns_down { p::DnsAnswer::Servfail } else { p::DnsAnswer::NoAnswer },
                transport: 0,
                qtype: 1,
            }),
        ));
        if net.dns_down {
            // A SERVFAIL is an answered query: success-with-bad-answer, not a timeout.
        }
        for (dev, mn, mx, sum, count) in &ble {
            if !cfg_loc {
                // Firmware still only emits enrolled devices; server drops when disabled.
            }
            let _ = w.push(&p::Record::Ble(p::BleSummary {
                age_ms: 0,
                window_ms: 2000,
                device_id: dev,
                count: *count,
                rssi_min: *mn,
                rssi_max: *mx,
                rssi_sum: *sum,
                last_seen_age_ms: 100,
                coverage_permille: 900,
            }));
        }
        if now >= n.next_scan {
            n.next_scan = now + 120_000;
            let mut entries = Vec::new();
            for r in &self.h.cfg.radios {
                let down = net.ap_down.as_deref() == Some(r.ap.as_str()) || net.ap_radio_down.as_deref() == Some(r.ap.as_str());
                if !down {
                    if let Some(m) = parse_mac(&r.bssid) {
                        entries.push(p::ApEntry { bssid: m, channel: r.channel.unwrap_or(1), rssi_dbm: -65 });
                    }
                }
            }
            let _ = w.push(&p::Record::ApScan(p::ApScan {
                age_ms: 0,
                scan_id: (seq % 60000) as u16,
                duration_ms: 1700,
                completeness: p::ScanCompleteness::Complete,
                channel_counts: [3, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0, 0],
                entries: p::ApEntries::List(&entries),
            }));
        }
        let len = w.finish();
        let topic = format!("{}/nodes/{node_id}/telemetry", self.h.cfg.topic_prefix());
        Some((topic, buf.get(..len)?.to_vec()))
    }

    fn events_frame(&mut self, idx: usize) -> Option<(String, Vec<u8>)> {
        let mono = { let n = &self.nodes[idx]; self.mono(n) };
        let n = &mut self.nodes[idx];
        if n.pending_life.is_empty() {
            return None;
        }
        n.seq += 1;
        let node_id = n.id.clone();
        let header = p::Header {
            kind: p::MsgKind::Events,
            flags: p::flags::NEEDS_ACK,
            node_id: &node_id,
            boot_id: n.boot,
            sequence: n.seq,
            sent_mono_ms: mono,
            config_revision: 1,
        };
        let mut buf = [0u8; p::MAX_FRAME_BYTES];
        let mut w = p::FrameWriter::new(&mut buf, &header, p::MAX_FRAME_BYTES).ok()?;
        for (ev, reason, prior, new) in n.pending_life.drain(..) {
            let _ = w.push(&p::Record::Lifecycle(p::Lifecycle {
                age_ms: 100,
                event: ev,
                reason,
                prior_bssid: prior,
                new_bssid: new,
                duration_ms: None,
            }));
        }
        let len = w.finish();
        Some((format!("{}/nodes/{node_id}/events", self.h.cfg.topic_prefix()), buf.get(..len)?.to_vec()))
    }

    fn central_checks(&mut self) {
        let checks = self.h.cfg.central_checks.clone();
        for c in checks {
            let due = *self.next_central.get(c.id.as_str()).unwrap_or(&self.now);
            if self.now < due {
                continue;
            }
            self.next_central.insert(c.id.to_string(), self.now + i64::from(c.interval_ms));
            let asset = c.asset.as_ref().map(|a| a.as_str().to_string()).unwrap_or_default();
            let wired_extra = if self.net.wired_congested { 60_000 } else { 0 };
            let up = match asset.as_str() {
                "wan-a" | "wan-b" => !self.net.wan_down,
                "app" => !self.net.app_down,
                a if Some(a) == self.net.ap_down.as_deref() => false,
                _ => true,
            };
            let lost = self.net.wired_congested && self.rng.gen_bool(0.12);
            let ok = up && !lost;
            let is_dns = c.kind == ProbeKindConf::Dns;
            let dns_bad = is_dns && self.net.dns_down;
            let rtt = (ok && !dns_bad).then(|| 400 + self.rng.gen_range(0..300) + wired_extra);
            let outcome = if ok { Outcome::Success } else { Outcome::Timeout };
            let probe = ProbeObs {
                target_id: c.id.to_string(),
                kind: ho_collectors_kind(c.kind).into(),
                outcome: if dns_bad { Outcome::Success } else { outcome },
                rtt_us: if dns_bad { Some(900) } else { rtt },
                scan_overlap: false,
                dscp: 0,
                sched_late_ms: 0,
                error_code: 0,
                dns: is_dns.then(|| DnsInfo {
                    rcode: if dns_bad { 2 } else { 0 },
                    answer: if dns_bad { "servfail".into() } else if ok { "match".into() } else { "no_answer".into() },
                    transport: "udp".into(),
                    qtype: 1,
                }),
                via_bssid: None,
            };
            self.central_seq += 1;
            let seq = self.central_seq;
            let now = self.now;
            self.h.central(now, seq, probe);
        }
    }

    /// Advance the world by `ms`, in 250 ms steps. Deterministic for a seed.
    pub fn run(&mut self, ms: i64) {
        let end = self.now + ms;
        while self.now < end {
            self.now += 250;
            for i in 0..self.nodes.len() {
                if self.now < self.nodes[i].next_report {
                    continue;
                }
                self.nodes[i].next_report += 2000;
                let reachable = { let n = &self.nodes[i]; self.node_reachable(n) };
                let mut frames = Vec::new();
                if let Some(f) = self.events_frame(i) {
                    frames.push(f);
                }
                if let Some(f) = self.node_frame(i) {
                    frames.push(f);
                }
                if !reachable {
                    // Node has no network path: nothing reaches the server.
                    continue;
                }
                if self.net.broker_down {
                    let n = &mut self.nodes[i];
                    for (_, f) in frames {
                        if n.offline_buffer.len() >= 8 {
                            n.offline_buffer.remove(0);
                            self.frames_dropped_offline += 1;
                        }
                        n.offline_buffer.push(f);
                    }
                    continue;
                }
                // Reconnected: drain a bounded amount of buffered history first.
                let backlog: Vec<Vec<u8>> = self.nodes[i].offline_buffer.drain(..).collect();
                let now = self.now;
                for f in backlog {
                    let id = self.nodes[i].id.clone();
                    let topic = format!("{}/nodes/{id}/telemetry", self.h.cfg.topic_prefix());
                    self.bytes_sent += f.len() as u64;
                    self.frames_sent += 1;
                    self.h.ingest(&topic, &f, now);
                }
                for (topic, f) in frames {
                    self.bytes_sent += f.len() as u64;
                    self.frames_sent += 1;
                    let jitter = self.rng.gen_range(2..40);
                    self.h.ingest(&topic, &f, now + jitter);
                }
            }
            self.central_checks();
            if self.now >= self.next_tick {
                self.next_tick = self.now + 1000;
                let now = self.now;
                if self.net.broker_down {
                    self.h.input(now, Input::Ingestion { ok: false, at: now });
                } else {
                    self.h.input(now, Input::Ingestion { ok: true, at: now });
                }
            }
        }
    }

    /// Generate a labeled calibration set by placing `device` in each room in turn.
    pub fn calibration(&mut self, device: &str, rounds: u32, session: &str) -> Vec<LabeledSample> {
        let rooms: Vec<String> = self.h.cfg.rooms.iter().map(|r| r.id.to_string()).collect();
        let mut out = Vec::new();
        for _ in 0..rounds {
            for room in &rooms {
                self.place(device, Some(room));
                let pos = self.devices.iter().find(|d| d.id == device).and_then(|d| d.pos).unwrap_or([0.0, 0.0]);
                let nodes: Vec<(String, [f64; 2], Option<String>)> = self
                    .nodes
                    .iter()
                    .map(|n| (n.id.clone(), n.pos, self.h.cfg.node(&n.id).and_then(|c| c.room.as_ref().map(ToString::to_string))))
                    .collect();
                for (id, npos, nroom) in nodes {
                    let same = nroom.as_deref() == Some(room.as_str());
                    let r = self.rssi(npos, pos, same);
                    if r > -98.0 {
                        out.push(LabeledSample { room: room.clone(), node: id, rssi: r, session: session.into() });
                    }
                }
            }
        }
        out
    }

    pub fn calibrated_model(&mut self, device: &str) -> RoomModel {
        let s = self.calibration(device, 40, "train");
        calibrate(&s, 1)
    }
}

fn ho_collectors_kind(k: ProbeKindConf) -> &'static str {
    match k {
        ProbeKindConf::Icmp => "icmp",
        ProbeKindConf::UdpEcho => "udp_echo",
        ProbeKindConf::Dns => "dns",
        ProbeKindConf::Tcp => "tcp",
        ProbeKindConf::Http => "http",
    }
}
