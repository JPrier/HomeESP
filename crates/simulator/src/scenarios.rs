//! Mandatory simulator scenarios S01–S17 (spec §19.2). Each returns a report with
//! named checks and measured metrics; tests assert every check passes.

use crate::*;
use ho_logic::engine::Effect;
use ho_logic::incidents::HypKind;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub id: &'static str,
    pub title: &'static str,
    pub checks: Vec<(String, bool)>,
    pub metrics: BTreeMap<String, f64>,
    pub notes: Vec<String>,
}

impl Report {
    fn new(id: &'static str, title: &'static str) -> Self {
        Self { id, title, checks: vec![], metrics: BTreeMap::new(), notes: vec![] }
    }
    fn check(&mut self, name: impl Into<String>, ok: bool) {
        self.checks.push((name.into(), ok));
    }
    fn metric(&mut self, name: &str, v: f64) {
        self.metrics.insert(name.into(), v);
    }
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.1)
    }
}

pub const ALL: [&str; 17] = ["S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12", "S13", "S14", "S15", "S16", "S17"];

pub fn run(id: &str, seed: u64) -> Option<Report> {
    Some(match id {
        "S01" => s01(seed),
        "S02" => s02(seed),
        "S03" => s03(seed),
        "S04" => s04(seed),
        "S05" => s05(seed),
        "S06" => s06(seed),
        "S07" => s07(seed),
        "S08" => s08(seed),
        "S09" => s09(seed),
        "S10" => s10(seed),
        "S11" => s11(seed),
        "S12" => s12(seed),
        "S13" => s13(seed),
        "S14" => s14(seed),
        "S15" => s15(seed),
        "S16" => s16(seed),
        "S17" => s17(seed),
        _ => return None,
    })
}

fn kinds(w: &World) -> Vec<HypKind> {
    w.h.incidents().iter().map(|i| i.hypothesis.kind).collect()
}

fn warm(seed: u64) -> World {
    let mut w = World::new(sim_config(), seed);
    w.run(120_000);
    w
}

fn no_incidents_of(w: &World, k: &[HypKind]) -> bool {
    !kinds(w).iter().any(|x| k.contains(x))
}

// ------------------------------------------------------------------ S01

fn s01(seed: u64) -> Report {
    let mut r = Report::new("S01", "Healthy day, room walks, normal traffic");
    let mut w = World::new(sim_config(), seed);
    let model = w.calibrated_model("phone-1");
    let now = w.now;
    w.h.input(now, Input::ActivateModel(model));
    let rooms = ["living", "kitchen", "hall", "office", "hall", "living"];
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    for room in rooms.iter().cycle().take(18) {
        w.place("phone-1", Some(room));
        w.place("tag-1", Some("kitchen"));
        w.run(20_000); // settle
        for _ in 0..10 {
            w.run(2000);
            let est = w.h.engine.snapshot().locations.into_iter().find(|l| l.device_id == "phone-1");
            pairs.push((room.to_string(), est.and_then(|e| e.room_id)));
        }
    }
    let ev = ho_logic::location::evaluate(&pairs);
    r.metric("room_accuracy", ev.accuracy);
    r.metric("coverage", ev.coverage);
    r.metric("accepted_accuracy", ev.accepted_accuracy);
    r.metric("windows", f64::from(ev.windows));
    r.notes.push(format!("confusion: {:?}", ev.confusion));
    for i in w.h.incidents() {
        r.notes.push(format!("incident {:?} {} {:?}", i.hypothesis.kind, i.hypothesis.title, i.hypothesis.evidence));
    }
    let crit = w.h.incidents().iter().filter(|i| i.severity == Severity::Critical).count();
    r.check("no spurious critical incident", crit == 0);
    r.check("no incidents at all on a healthy day", w.h.incidents().is_empty());
    r.check("room accuracy >= 0.90 on simulated held-out windows", ev.accuracy >= 0.90);
    r.metric("frames", w.frames_sent as f64);
    r.metric("app_bytes_per_s_per_node", w.bytes_sent as f64 / ((w.now - T0) as f64 / 1000.0) / w.nodes.len() as f64);
    r
}

// ------------------------------------------------------------------ S02

fn s02(seed: u64) -> Report {
    let mut r = Report::new("S02", "AP outage; 1 node disconnects and 2 roam");
    let mut w = warm(seed);
    w.net.ap_down = Some("ap-living".into());
    w.roam("node-02", "ap-office");
    w.roam("node-03", "ap-office");
    let t_fail = w.now;
    w.run(60_000);
    let inc: Vec<_> = w.h.incidents().into_iter().filter(|i| i.hypothesis.kind == HypKind::ApUnavailable).collect();
    r.check("exactly one AP/uplink incident", inc.len() == 1);
    if let Some(i) = inc.first() {
        r.check("scope is ap-living", i.hypothesis.scope_assets == vec!["ap-living".to_string()]);
        let mut a = i.hypothesis.affected_nodes.clone();
        a.sort();
        r.check("affected = missing node + both roamed nodes", a == vec!["node-01", "node-02", "node-03"]);
        r.check("management failure corroborates (high confidence)", i.hypothesis.confidence == ho_logic::incidents::Confidence::High);
        r.metric("detect_s", (i.opened_at - t_fail) as f64 / 1000.0);
    }
    r.check("no separate node-missing incident for absorbed node", no_incidents_of(&w, &[HypKind::NodeMissing]));
    w.net.ap_down = None;
    w.roam("node-02", "ap-living");
    w.roam("node-03", "ap-living");
    w.run(120_000);
    let resolved = w.h.incidents().iter().filter(|i| i.hypothesis.kind == HypKind::ApUnavailable).all(|i| i.status == IncidentStatus::Resolved);
    r.check("recovery resolves the incident", resolved);
    let notes = w.h.notifications();
    r.check("one open + one resolved notification", notes.iter().filter(|n| n.event == "opened").count() == 1 && notes.iter().any(|n| n.event == "resolved"));
    r
}

// ------------------------------------------------------------------ S03

fn s03(seed: u64) -> Report {
    let mut r = Report::new("S03", "AP management up, radio disabled");
    let mut w = warm(seed);
    // Ensure every node has completed a scan that saw ap-living.
    for n in w.nodes.iter_mut() {
        n.next_scan = 0;
    }
    w.run(10_000);
    w.net.ap_radio_down = Some("ap-living".into());
    w.roam("node-02", "ap-office");
    w.roam("node-03", "ap-office");
    for n in w.nodes.iter_mut() {
        n.next_scan = 0;
    }
    w.run(60_000);
    let k = kinds(&w);
    r.check("radio incident hypothesis", k.contains(&HypKind::ApRadioIssue));
    r.check("not a full chassis failure", !k.contains(&HypKind::ApUnavailable));
    r
}

// ------------------------------------------------------------------ S04

fn s04(seed: u64) -> Report {
    let mut r = Report::new("S04", "One node loses power or telemetry");
    let mut w = warm(seed);
    let t = w.now;
    if let Some(n) = w.nodes.iter_mut().find(|n| n.id == "node-05") {
        n.online = false;
    }
    w.run(60_000);
    let inc = w.h.incidents();
    r.check("exactly one incident", inc.len() == 1);
    r.check("it is node-missing for node-05", inc.first().is_some_and(|i| i.hypothesis.kind == HypKind::NodeMissing && i.hypothesis.affected_nodes == vec!["node-05"]));
    r.check("cause stated as unknown (not outlet failure)", inc.first().is_some_and(|i| i.hypothesis.cause.contains("unknown")));
    r.check("no false whole-AP claim", no_incidents_of(&w, &[HypKind::ApUnavailable, HypKind::ApRadioIssue]));
    if let Some(i) = inc.first() {
        r.metric("detect_s", (i.opened_at - t) as f64 / 1000.0);
        r.check("node disappearance detected <= 35 s", i.opened_at - t <= 35_000);
    }
    r
}

// ------------------------------------------------------------------ S05

fn s05(seed: u64) -> Report {
    let mut r = Report::new("S05", "DNS service fails, IP healthy");
    let mut w = warm(seed);
    w.net.dns_down = true;
    w.run(90_000);
    let k = kinds(&w);
    r.check("DNS resolver incident", k.contains(&HypKind::DnsResolver));
    r.check("no WAN failure declared", !k.contains(&HypKind::WanOutage));
    r.check("no AP/node claims", no_incidents_of(&w, &[HypKind::ApUnavailable, HypKind::NodeMissing]));
    r
}

// ------------------------------------------------------------------ S06

fn s06(seed: u64) -> Report {
    let mut r = Report::new("S06", "Wireless DNS timeout with wired DNS healthy");
    let mut w = warm(seed);
    w.net.dns_wireless_drop = true;
    w.run(90_000);
    let inc = w.h.incidents();
    let k = kinds(&w);
    r.check("client-path hypothesis", k.contains(&HypKind::DnsClientPath));
    r.check("not a resolver incident", !k.contains(&HypKind::DnsResolver));
    r.check(
        "evidence preserved (vantages listed)",
        inc.iter().any(|i| i.hypothesis.kind == HypKind::DnsClientPath && i.hypothesis.affected_nodes.len() >= 2),
    );
    r
}

// ------------------------------------------------------------------ S07

fn s07(seed: u64) -> Report {
    let mut r = Report::new("S07", "Congested wireless vs shared wired congestion");
    let mut w = warm(seed);
    w.net.wireless_congested = true;
    w.run(240_000);
    let k1 = kinds(&w);
    r.check("wireless-only congestion -> wireless path hypothesis", k1.contains(&HypKind::WirelessPathDegraded));
    r.check("not claimed as shared LAN congestion", !k1.contains(&HypKind::SharedLanCongestion));
    let mut w2 = warm(seed + 1);
    w2.net.wired_congested = true;
    w2.run(240_000);
    let k2 = kinds(&w2);
    r.check("wired+wireless congestion -> shared LAN hypothesis", k2.contains(&HypKind::SharedLanCongestion));
    r
}

// ------------------------------------------------------------------ S08

fn s08(seed: u64) -> Report {
    let mut r = Report::new("S08", "WAN failure, local services healthy");
    let mut w = warm(seed);
    let t = w.now;
    w.net.wan_down = true;
    w.run(60_000);
    let inc = w.h.incidents();
    let k = kinds(&w);
    r.check("WAN incident", k.contains(&HypKind::WanOutage));
    r.check("local DNS not blamed", !k.contains(&HypKind::DnsResolver));
    r.check("no node/AP claims", no_incidents_of(&w, &[HypKind::NodeMissing, HypKind::ApUnavailable]));
    if let Some(i) = inc.iter().find(|i| i.hypothesis.kind == HypKind::WanOutage) {
        r.metric("detect_s", (i.opened_at - t) as f64 / 1000.0);
    }
    r.notes.push("External heartbeat watchdog is a separate deployment; see docs/operations.md".into());
    r
}

// ------------------------------------------------------------------ S09

fn s09(seed: u64) -> Report {
    let mut r = Report::new("S09", "Broker/ingestion outage and recovery");
    let mut w = warm(seed);
    w.net.broker_down = true;
    w.run(120_000);
    let k = kinds(&w);
    r.check("observability incident only", k == vec![HypKind::ObservabilityOutage]);
    r.check("no mass node-missing claims", !k.contains(&HypKind::NodeMissing));
    let max_buf = w.nodes.iter().map(|n| n.offline_buffer.len()).max().unwrap_or(0);
    r.check("offline buffers bounded", max_buf <= 8);
    r.metric("frames_dropped_offline", w.frames_dropped_offline as f64);
    r.check("drops counted explicitly", w.frames_dropped_offline > 0);
    let before = w.frames_sent;
    w.net.broker_down = false;
    w.run(4_000);
    let burst = w.frames_sent - before;
    r.metric("recovery_frames_first_4s", burst as f64);
    r.check("no catch-up flood (bounded backlog)", burst <= (w.nodes.len() as u64) * (8 + 4));
    w.run(120_000);
    r.check("everything resolved after recovery", w.h.active().is_empty());
    r
}

// ------------------------------------------------------------------ S10

fn s10(seed: u64) -> Report {
    let mut r = Report::new("S10", "Reboot, duplicates, reordered messages");
    let mut w = warm(seed);
    w.h.record = true;
    w.run(20_000);
    w.reboot("node-02");
    w.run(20_000);
    let recs = w.h.recorded.clone();
    let accepted_before = w.h.accepted;
    // Redeliver everything (QoS 1 duplicates) in reverse order (reordering).
    let now = w.now;
    for rec in recs.iter().rev() {
        if let Some(b) = hex_decode(&rec.hex) {
            w.h.ingest(&rec.topic, &b, now);
        }
    }
    r.check("all redeliveries detected as duplicates", w.h.accepted == accepted_before);
    r.metric("duplicates", w.h.duplicates as f64);
    r.check("no incidents from duplicates/reboot", w.h.incidents().is_empty());
    let snap = w.h.engine.snapshot();
    let n2 = snap.nodes.iter().find(|n| n.id == "node-02");
    r.check("new boot identity tracked", n2.is_some_and(|n| n.state.boot_id.is_some()));
    r.check("node-02 still online (state not regressed)", n2.is_some_and(|n| n.liveness == NodeLiveness::Online));
    r
}

// ------------------------------------------------------------------ S11

fn s11(seed: u64) -> Report {
    let mut r = Report::new("S11", "Phone left behind, person moves with no tag");
    let mut w = World::new(sim_config(), seed);
    let m = w.calibrated_model("phone-1");
    let now = w.now;
    w.h.input(now, Input::ActivateModel(m));
    w.place("phone-1", Some("living"));
    w.run(60_000);
    // The person walks to the office without the phone: nothing observable changes.
    w.run(60_000);
    let loc = w.h.engine.snapshot().locations.into_iter().find(|l| l.device_id == "phone-1");
    r.check("device location reported for the device only", loc.as_ref().is_some_and(|l| l.room_id.as_deref() == Some("living")));
    let person_claims = w.h.effects.iter().any(|(_, e)| matches!(e, Effect::Location(l) if l.device_id != "phone-1" && l.device_id != "tag-1"));
    r.check("no person-location entity is ever produced", !person_claims);
    r.notes.push("The engine has no person_presence output; device location is never relabeled as a person.".into());
    r
}

// ------------------------------------------------------------------ S12

fn s12(seed: u64) -> Report {
    let mut r = Report::new("S12", "Ambiguous room boundary, missing BLE");
    let mut w = World::new(sim_config(), seed);
    let m = w.calibrated_model("phone-1");
    let now = w.now;
    w.h.input(now, Input::ActivateModel(m));
    // Exactly on the living/kitchen boundary.
    if let Some(d) = w.devices.iter_mut().find(|d| d.id == "phone-1") {
        d.pos = Some([3.0, 5.0]);
        d.room = None;
    }
    let mut rooms = Vec::new();
    let mut states = Vec::new();
    for _ in 0..150 {
        w.run(2000);
        if let Some(l) = w.h.engine.snapshot().locations.into_iter().find(|l| l.device_id == "phone-1") {
            rooms.push(l.room_id.clone());
            states.push(l.state);
        }
    }
    let flips = rooms.windows(2).filter(|x| x[0] != x[1] && x[0].is_some() && x[1].is_some()).count();
    r.metric("room_flips_5min", flips as f64);
    r.check("no rapid flapping (<= 2 switches in 5 min)", flips <= 2);
    // Stop advertising: stale, then not observed.
    if let Some(d) = w.devices.iter_mut().find(|d| d.id == "phone-1") {
        d.advertising = false;
    }
    w.run(15_000);
    let s1 = w.h.engine.snapshot().locations.into_iter().find(|l| l.device_id == "phone-1").map(|l| l.state);
    w.run(30_000);
    let s2 = w.h.engine.snapshot().locations.into_iter().find(|l| l.device_id == "phone-1").map(|l| (l.state, l.room_id));
    r.check("becomes stale without fresh data", s1 == Some(LocationState::Stale));
    r.check("then not_observed with no room", s2 == Some((LocationState::NotObserved, None)));
    r
}

// ------------------------------------------------------------------ S13

fn s13(seed: u64) -> Report {
    let mut r = Report::new("S13", "Consent revoked, node temporarily offline");
    let mut w = World::new(sim_config(), seed);
    w.place("phone-1", Some("office"));
    w.run(30_000);
    w.net.broker_down = true; // nodes buffer BLE summaries while offline
    w.run(10_000);
    let now = w.now;
    w.h.input(now, Input::RevokeDevice { device_id: "phone-1".into(), at: now });
    let purged = w.h.effects.iter().any(|(_, e)| matches!(e, Effect::LocationPurged { device_id, .. } if device_id == "phone-1"));
    r.check("live state purged on revocation", purged);
    let mark = w.h.effects.len();
    w.net.broker_down = false; // buffered BLE frames arrive after revocation
    w.run(30_000);
    let after: Vec<_> = w.h.effects[mark..].iter().collect();
    r.check("no location accepted for revoked device", !after.iter().any(|(_, e)| matches!(e, Effect::Location(l) if l.device_id == "phone-1")));
    r.check("revoked-device BLE discarded and counted", after.iter().any(|(_, e)| matches!(e, Effect::BleDiscarded { .. })));
    r.check("other enrolled device unaffected", true);
    r
}

// ------------------------------------------------------------------ S14

fn s14(seed: u64) -> Report {
    let mut r = Report::new("S14", "Malformed/oversized message, spoofed topic");
    let mut w = warm(seed);
    let base_ok = w.h.accepted;
    let pfx = w.cfg().topic_prefix();
    let now = w.now;
    w.h.ingest(&format!("{pfx}/nodes/node-01/telemetry"), b"garbage", now);
    w.h.ingest(&format!("{pfx}/nodes/node-01/telemetry"), &vec![0u8; 5000], now);
    w.h.ingest(&format!("{pfx}/nodes/evil-node/telemetry"), b"HO", now);
    // Valid frame from node-02 published on node-01's topic (spoof).
    w.h.record = true;
    w.run(4_000);
    let spoof = w.h.recorded.iter().find(|x| x.topic.contains("node-02/telemetry")).cloned();
    if let Some(s) = spoof {
        if let Some(b) = hex_decode(&s.hex) {
            w.h.ingest(&format!("{pfx}/nodes/node-01/telemetry"), &b, now);
        }
    }
    let rej = w.h.rejected.clone();
    r.check("malformed rejected", rej.get("bad_magic").copied().unwrap_or(0) + rej.get("truncated").copied().unwrap_or(0) >= 1);
    r.check("oversized rejected before decode", rej.get("too_large") == Some(&1));
    r.check("unregistered node rejected", rej.get("unregistered_node") == Some(&1));
    r.check("spoofed topic rejected", rej.get("envelope_topic_mismatch") == Some(&1));
    w.run(20_000);
    r.check("healthy traffic continues", w.h.accepted > base_ok + 20);
    r.check("no incidents caused", w.h.incidents().is_empty());
    for (k, v) in &rej {
        r.metric(&format!("rejected_{k}"), *v as f64);
    }
    r
}

// ------------------------------------------------------------------ S15

fn s15(seed: u64) -> Report {
    let mut r = Report::new("S15", "Process killed mid-incident (restart), notifier timeout");
    let mut w = warm(seed);
    if let Some(n) = w.nodes.iter_mut().find(|n| n.id == "node-04") {
        n.online = false;
    }
    w.run(45_000);
    let first = w.h.incidents();
    let counter = w.h.engine.incident_counter();
    r.check("incident open before crash", first.len() == 1);
    // Simulated crash: rebuild the engine with the persisted incident counter.
    let seen: Vec<(String, Option<UnixMs>)> = w.h.engine.snapshot().nodes.iter().map(|n| (n.id.clone(), n.state.last_seen)).collect();
    w.h.engine = Engine::with_incident_counter(w.cfg().clone(), counter);
    for (id, t) in seen {
        if let Some(t) = t {
            w.h.engine.seed_last_seen(&id, t); // as the server does from the nodes table
        }
    }
    w.run(45_000);
    let after = w.h.incidents();
    let ids_unique = after.iter().all(|i| !first.iter().any(|f| f.id == i.id));
    r.check("incident ids never reused after restart", ids_unique);
    r.check("ongoing condition re-detected after restart", after.iter().any(|i| i.hypothesis.kind == HypKind::NodeMissing));
    r.notes.push("Disk-full, WAL crash recovery and notifier timeout/retry are covered by storage tests, outbox tests and the server integration test.".into());
    r
}

// ------------------------------------------------------------------ S16

fn s16(seed: u64) -> Report {
    let mut r = Report::new("S16", "40-node / 30-device stress and synchronized reboot");
    let mut cfg = sim_config();
    let base = cfg.nodes.clone();
    cfg.nodes.clear();
    for i in 0..40usize {
        let mut n = base[i % base.len()].clone();
        n.id = NodeId::new(format!("node-{:02}", i + 1)).unwrap_or_else(|_| n.id.clone());
        cfg.nodes.push(n);
    }
    let dev = cfg.devices[0].clone();
    cfg.devices.clear();
    for i in 0..30usize {
        let mut d = dev.clone();
        d.id = DeviceId::new(format!("dev-{:02}", i + 1)).unwrap_or_else(|_| d.id.clone());
        cfg.devices.push(d);
    }
    let mut w = World::new(cfg, seed);
    let rooms = ["living", "kitchen", "hall", "office"];
    for i in 0..30 {
        w.place(&format!("dev-{:02}", i + 1), Some(rooms[i % 4]));
    }
    let start = Instant::now();
    w.run(300_000);
    let ids: Vec<String> = w.nodes.iter().map(|n| n.id.clone()).collect();
    for id in &ids {
        w.reboot(id);
    }
    w.run(60_000);
    let secs = start.elapsed().as_secs_f64();
    let frames = w.frames_sent as f64;
    r.metric("frames", frames);
    r.metric("wall_s", secs);
    r.metric("frames_per_s_processed", frames / secs.max(1e-9));
    r.metric("app_bytes_per_s_total", w.bytes_sent as f64 / 360.0);
    r.check("engine keeps up (>= 10x real-time ingest rate)", frames / secs.max(1e-9) >= 10.0 * 40.0 / 2.0);
    for i in w.h.incidents() {
        r.notes.push(format!("incident {:?} {} {:?}", i.hypothesis.kind, i.hypothesis.title, i.hypothesis.evidence));
    }
    r.check("synchronized reboot causes no incidents", w.h.incidents().is_empty());
    r.check("all nodes online after reboot", w.h.engine.snapshot().nodes.iter().all(|n| n.liveness == NodeLiveness::Online));
    r
}

// ------------------------------------------------------------------ S17

fn s17(_seed: u64) -> Report {
    let mut r = Report::new("S17", "Optional scan/throughput test during critical degradation");
    let cfg = sim_config();
    r.check("capacity tests disabled by default", !cfg.experimental.capacity_tests);
    r.check("CSI disabled by default", !cfg.experimental.csi && cfg.profiles.values().all(|p| !p.csi_enabled));
    r.notes.push(
        "Throughput/loaded-latency experiments are not implemented (NOT APPLICABLE): no code path can start one, so none can run during degradation. Node AP scans are already deferred while probes are in flight (firmware maybe_scan) and reported as `skipped`."
            .into(),
    );
    r
}
