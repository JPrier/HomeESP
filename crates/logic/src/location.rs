//! Room-level localization of enrolled devices (spec §10.3).
//!
//! Pipeline per device: robust per-node smoothing (EMA over window means) ->
//! per-room log-likelihood from calibrated fingerprints (or an explicitly labeled
//! uncalibrated nearest-node fallback) -> discrete HMM over room adjacency with
//! elapsed-time transitions -> hysteresis -> explicit state. Missing data decays to
//! `stale` / `not_observed`; it is never treated as a weak signal.

use ho_domain::{LocationState, LocationThresholds, UnixMs};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// RSSI used for "configured node did not hear the device although it was scanning".
const NON_DETECT_DBM: f64 = -100.0;
/// Cap on a single node's (negative) log-likelihood contribution.
const OUTLIER_CAP: f64 = 8.0;
/// Minimum sigma (dB) so tiny calibration spreads cannot dominate.
const SIGMA_FLOOR: f64 = 3.0;

/// Calibrated fingerprint model, versioned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RoomModel {
    pub revision: u32,
    /// room -> node -> (median RSSI dBm, robust sigma dB)
    pub fingerprints: BTreeMap<String, BTreeMap<String, (f64, f64)>>,
}

impl RoomModel {
    pub fn is_calibrated(&self) -> bool {
        !self.fingerprints.is_empty()
    }
}

/// One labeled calibration sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabeledSample {
    pub room: String,
    pub node: String,
    pub rssi: f64,
    pub session: String,
}

/// Fit a model from labeled samples using median and MAD (robust to outliers).
pub fn calibrate(samples: &[LabeledSample], revision: u32) -> RoomModel {
    let mut by: BTreeMap<(&str, &str), Vec<f64>> = BTreeMap::new();
    for s in samples.iter().filter(|s| s.rssi.is_finite()) {
        by.entry((s.room.as_str(), s.node.as_str())).or_default().push(s.rssi);
    }
    let mut m = RoomModel { revision, fingerprints: BTreeMap::new() };
    for ((room, node), v) in by {
        if v.len() < 5 {
            continue; // insufficient samples: leave unknown rather than guess
        }
        if let Some((med, mad)) = crate::stats::median_mad(&v) {
            let sigma = (1.4826 * mad).max(SIGMA_FLOOR);
            m.fingerprints.entry(room.to_string()).or_default().insert(node.to_string(), (med, sigma));
        }
    }
    m
}

/// Room topology for the HMM.
#[derive(Debug, Clone, Default)]
pub struct RoomGraph {
    pub rooms: Vec<String>,
    pub neighbors: BTreeMap<String, BTreeSet<String>>,
    /// node -> room it is installed in (for the nearest-node fallback).
    pub node_room: BTreeMap<String, String>,
}

impl RoomGraph {
    pub fn from_config(cfg: &ho_domain::SiteConfig) -> Self {
        let rooms: Vec<String> = cfg.rooms.iter().map(|r| r.id.to_string()).collect();
        let mut neighbors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for e in &cfg.room_edges {
            neighbors.entry(e.from.to_string()).or_default().insert(e.to.to_string());
            if e.bidirectional {
                neighbors.entry(e.to.to_string()).or_default().insert(e.from.to_string());
            }
        }
        let node_room = cfg.nodes.iter().filter_map(|n| n.room.as_ref().map(|r| (n.id.to_string(), r.to_string()))).collect();
        Self { rooms, neighbors, node_room }
    }
}

/// Published location estimate (spec §10.3 step 6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocationEstimate {
    pub device_id: String,
    pub room_id: Option<String>,
    pub last_known_room: Option<String>,
    pub confidence: f64,
    pub state: LocationState,
    pub observed_at: Option<UnixMs>,
    pub age_ms: Option<i64>,
    pub model_revision: u32,
    pub calibrated: bool,
    pub contributing_nodes: Vec<String>,
    pub alternatives: Vec<(String, f64)>,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct Smoothed {
    value: f64,
    last_t: UnixMs,
    coverage: f64,
}

/// Per-device filter state.
#[derive(Debug, Clone)]
pub struct DeviceTracker {
    pub device_id: String,
    smoothed: BTreeMap<String, Smoothed>,
    posterior: BTreeMap<String, f64>,
    current: Option<String>,
    candidate: Option<(String, u32)>,
    last_obs: Option<UnixMs>,
    last_step: Option<UnixMs>,
    last_emitted: Option<LocationEstimate>,
}

impl DeviceTracker {
    pub fn new(device_id: &str) -> Self {
        Self {
            device_id: device_id.into(),
            smoothed: BTreeMap::new(),
            posterior: BTreeMap::new(),
            current: None,
            candidate: None,
            last_obs: None,
            last_step: None,
            last_emitted: None,
        }
    }

    /// Feed one per-node window summary (mean RSSI over the window).
    pub fn observe(&mut self, node: &str, t: UnixMs, mean_rssi: f64, coverage: f64, th: &LocationThresholds) {
        if !mean_rssi.is_finite() {
            return;
        }
        // Late samples beyond the lateness allowance never move current state.
        if self.last_obs.is_some_and(|l| t < l - th.lateness_ms) {
            return;
        }
        let e = self.smoothed.entry(node.to_string()).or_insert(Smoothed { value: mean_rssi, last_t: t, coverage });
        if t >= e.last_t {
            e.value = th.ema_alpha * mean_rssi + (1.0 - th.ema_alpha) * e.value;
            e.last_t = t;
            e.coverage = coverage;
        }
        self.last_obs = Some(self.last_obs.map_or(t, |l| l.max(t)));
    }

    fn likelihoods(&self, now: UnixMs, model: &RoomModel, g: &RoomGraph, th: &LocationThresholds, scanning: &BTreeSet<String>) -> (BTreeMap<String, f64>, Vec<String>) {
        let fresh: BTreeMap<&str, &Smoothed> = self
            .smoothed
            .iter()
            .filter(|(_, s)| now - s.last_t <= th.stale_ms)
            .map(|(n, s)| (n.as_str(), s))
            .collect();
        let contributing: Vec<String> = fresh.keys().map(|s| s.to_string()).collect();
        let mut ll = BTreeMap::new();
        if model.is_calibrated() {
            for room in &g.rooms {
                let fp = model.fingerprints.get(room);
                let mut sum = 0.0;
                for (node, (mu, sigma)) in fp.into_iter().flatten() {
                    let sigma = sigma.max(th.sigma_db.min(*sigma).max(SIGMA_FLOOR));
                    let (x, w) = match fresh.get(node.as_str()) {
                        Some(s) => (s.value, s.coverage.clamp(0.1, 1.0)),
                        // Non-detection counts only when that node is known to be scanning.
                        None if scanning.contains(node) => (NON_DETECT_DBM, 0.5),
                        None => continue,
                    };
                    let z = (x - mu) / sigma;
                    sum += w * (-0.5 * z * z).max(-OUTLIER_CAP);
                }
                ll.insert(room.clone(), sum);
            }
        } else {
            // Uncalibrated nearest-node fallback: each room scores its strongest node.
            for room in &g.rooms {
                let best = fresh
                    .iter()
                    .filter(|(n, _)| g.node_room.get(**n) == Some(room))
                    .map(|(_, s)| s.value)
                    .fold(f64::NEG_INFINITY, f64::max);
                let score = if best.is_finite() { best / th.sigma_db } else { NON_DETECT_DBM / th.sigma_db };
                ll.insert(room.clone(), score);
            }
        }
        (ll, contributing)
    }

    fn predict(&mut self, dt_ms: i64, g: &RoomGraph) {
        if self.posterior.is_empty() {
            let u = 1.0 / g.rooms.len().max(1) as f64;
            self.posterior = g.rooms.iter().map(|r| (r.clone(), u)).collect();
            return;
        }
        let steps = (dt_ms / 3000).clamp(1, 20);
        let stay = 0.8;
        let leak = 0.01; // never hard-constrain to impossible rooms after missing evidence
        for _ in 0..steps {
            let mut next: BTreeMap<String, f64> = g.rooms.iter().map(|r| (r.clone(), 0.0)).collect();
            for (r, p) in &self.posterior {
                let nb = g.neighbors.get(r);
                let n = nb.map_or(0, BTreeSet::len);
                let keep = if n == 0 { 1.0 - leak } else { stay };
                *next.entry(r.clone()).or_default() += p * keep;
                if let Some(nb) = nb {
                    for u in nb {
                        *next.entry(u.clone()).or_default() += p * (1.0 - stay - leak) / n as f64;
                    }
                }
                let share = p * leak / g.rooms.len().max(1) as f64;
                for room in &g.rooms {
                    *next.entry(room.clone()).or_default() += share;
                }
            }
            normalize(&mut next);
            self.posterior = next;
        }
    }

    /// Advance the filter to `now` and produce the current estimate.
    pub fn step(
        &mut self,
        now: UnixMs,
        model: &RoomModel,
        g: &RoomGraph,
        th: &LocationThresholds,
        scanning: &BTreeSet<String>,
    ) -> LocationEstimate {
        let age = self.last_obs.map(|t| now - t);
        let calibrated = model.is_calibrated();
        let device_id = self.device_id.clone();
        let last_obs = self.last_obs;
        let base = |state, room: Option<String>, conf: f64, reason: &str, contributing: Vec<String>, alts, last_known: Option<String>| LocationEstimate {
            device_id: device_id.clone(),
            room_id: room,
            last_known_room: last_known,
            confidence: conf,
            state,
            observed_at: last_obs,
            age_ms: age,
            model_revision: model.revision,
            calibrated,
            contributing_nodes: contributing,
            alternatives: alts,
            reason: reason.into(),
        };
        match age {
            None => return base(LocationState::NotObserved, None, 0.0, "never observed", vec![], vec![], None),
            Some(a) if a > th.not_observed_ms => {
                self.posterior.clear();
                self.candidate = None;
                return base(LocationState::NotObserved, None, 0.0, "no observations within not-observed timeout", vec![], vec![], self.current.clone());
            }
            Some(a) if a > th.stale_ms => {
                // Last-known room is labeled, never presented as fresh truth.
                return base(LocationState::Stale, None, 0.0, "observations stale", vec![], vec![], self.current.clone());
            }
            _ => {}
        }
        let dt = self.last_step.map_or(th.window_ms, |l| now - l);
        self.last_step = Some(now);
        self.predict(dt, g);
        let (ll, contributing) = self.likelihoods(now, model, g, th, scanning);
        let max_ll = ll.values().copied().fold(f64::NEG_INFINITY, f64::max);
        for (r, p) in self.posterior.iter_mut() {
            let l = ll.get(r).copied().unwrap_or(max_ll - OUTLIER_CAP);
            *p = (p.max(1e-12)).ln() + (l - max_ll);
        }
        log_normalize(&mut self.posterior);
        let mut ranked: Vec<(String, f64)> = self.posterior.iter().map(|(r, p)| (r.clone(), *p)).collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let (top, p_top) = ranked.first().cloned().unwrap_or_default();
        let p_second = ranked.get(1).map_or(0.0, |x| x.1);
        let alts: Vec<(String, f64)> = ranked.iter().skip(1).take(2).cloned().collect();
        let reason_mode = if calibrated { "calibrated fingerprint" } else { "uncalibrated nearest-node (lower confidence)" };
        let confident = p_top >= th.min_confidence && p_top - p_second >= th.min_margin;

        if Some(&top) != self.current.as_ref() {
            if confident {
                let c = self.candidate.get_or_insert((top.clone(), 0));
                if c.0 != top {
                    *c = (top.clone(), 0);
                }
                c.1 += 1;
                if c.1 >= th.consecutive_windows {
                    self.current = Some(top.clone());
                    self.candidate = None;
                }
            } else {
                self.candidate = None;
            }
        } else {
            self.candidate = None;
        }
        let cur_p = self.current.as_ref().and_then(|c| self.posterior.get(c)).copied().unwrap_or(0.0);
        let est = if self.current.is_some() && cur_p >= th.min_confidence && (self.current.as_ref() == Some(&top)) {
            base(LocationState::Located, self.current.clone(), cur_p, reason_mode, contributing, alts, self.current.clone())
        } else {
            base(
                LocationState::Ambiguous,
                None,
                p_top,
                &format!("{reason_mode}: insufficient confidence/margin ({p_top:.2} vs {p_second:.2})"),
                contributing,
                ranked.iter().take(3).cloned().collect(),
                self.current.clone(),
            )
        };
        est
    }

    /// Returns the estimate only if it differs materially from the last emitted one.
    pub fn changed(&mut self, est: LocationEstimate) -> Option<LocationEstimate> {
        let differs = self
            .last_emitted
            .as_ref()
            .is_none_or(|l| l.state != est.state || l.room_id != est.room_id || (l.confidence - est.confidence).abs() > 0.1);
        if differs {
            self.last_emitted = Some(est.clone());
            Some(est)
        } else {
            None
        }
    }
}

fn normalize(m: &mut BTreeMap<String, f64>) {
    let s: f64 = m.values().sum();
    if s > 0.0 && s.is_finite() {
        for v in m.values_mut() {
            *v /= s;
        }
    }
}

/// Stable normalization of log-probabilities via log-sum-exp.
fn log_normalize(m: &mut BTreeMap<String, f64>) {
    let max = m.values().copied().fold(f64::NEG_INFINITY, f64::max);
    if !max.is_finite() {
        let u = 1.0 / m.len().max(1) as f64;
        for v in m.values_mut() {
            *v = u;
        }
        return;
    }
    let lse = max + m.values().map(|v| (v - max).exp()).sum::<f64>().ln();
    for v in m.values_mut() {
        *v = (*v - lse).exp();
    }
}

/// Confusion matrix + accuracy/coverage over held-out labeled windows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Evaluation {
    pub windows: u32,
    pub correct: u32,
    pub unknown: u32,
    /// Headline: correct / windows (unknown counts as not correct).
    pub accuracy: f64,
    /// Fraction of windows with a located answer.
    pub coverage: f64,
    /// correct / located windows.
    pub accepted_accuracy: f64,
    pub confusion: BTreeMap<String, BTreeMap<String, u32>>,
}

pub fn evaluate(pairs: &[(String, Option<String>)]) -> Evaluation {
    let mut e = Evaluation::default();
    for (truth, pred) in pairs {
        e.windows += 1;
        let p = pred.clone().unwrap_or_else(|| "unknown".into());
        if pred.is_none() {
            e.unknown += 1;
        } else if pred.as_ref() == Some(truth) {
            e.correct += 1;
        }
        *e.confusion.entry(truth.clone()).or_default().entry(p).or_default() += 1;
    }
    if e.windows > 0 {
        e.accuracy = f64::from(e.correct) / f64::from(e.windows);
        e.coverage = f64::from(e.windows - e.unknown) / f64::from(e.windows);
    }
    let located = e.windows - e.unknown;
    if located > 0 {
        e.accepted_accuracy = f64::from(e.correct) / f64::from(located);
    }
    e
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn graph() -> RoomGraph {
        let mut g = RoomGraph {
            rooms: vec!["hall".into(), "kitchen".into(), "living".into()],
            ..Default::default()
        };
        for (a, b) in [("living", "hall"), ("hall", "kitchen")] {
            g.neighbors.entry(a.into()).or_default().insert(b.into());
            g.neighbors.entry(b.into()).or_default().insert(a.into());
        }
        g.node_room = [("n-l", "living"), ("n-h", "hall"), ("n-k", "kitchen")]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        g
    }

    fn model() -> RoomModel {
        let mut s = Vec::new();
        let truth = [("living", [-55.0, -70.0, -85.0]), ("hall", [-70.0, -55.0, -70.0]), ("kitchen", [-85.0, -70.0, -55.0])];
        for (room, means) in truth {
            for (node, mu) in ["n-l", "n-h", "n-k"].iter().zip(means) {
                for k in 0..10 {
                    s.push(LabeledSample {
                        room: room.into(),
                        node: node.to_string(),
                        rssi: mu + f64::from(k % 5) - 2.0,
                        session: "a".into(),
                    });
                }
            }
        }
        calibrate(&s, 3)
    }

    fn feed(t: &mut DeviceTracker, now: UnixMs, r: [f64; 3], th: &LocationThresholds) {
        for (n, v) in ["n-l", "n-h", "n-k"].iter().zip(r) {
            t.observe(n, now, v, 1.0, th);
        }
    }

    #[test]
    fn locates_with_hysteresis_and_transitions() {
        let th = LocationThresholds::default();
        let (g, m) = (graph(), model());
        let scanning: BTreeSet<String> = g.node_room.keys().cloned().collect();
        let mut t = DeviceTracker::new("phone-1");
        let mut now = 0;
        let mut last = None;
        for _ in 0..4 {
            now += 2000;
            feed(&mut t, now, [-55.0, -71.0, -84.0], &th);
            last = Some(t.step(now, &m, &g, &th, &scanning));
        }
        let e = last.unwrap();
        assert_eq!(e.state, LocationState::Located);
        assert_eq!(e.room_id.as_deref(), Some("living"));
        assert!(e.calibrated && e.model_revision == 3);
        // Walk to the kitchen: must pass hysteresis, never flip on one window.
        now += 2000;
        feed(&mut t, now, [-85.0, -70.0, -55.0], &th);
        let e1 = t.step(now, &m, &g, &th, &scanning);
        assert_ne!(e1.room_id.as_deref(), Some("kitchen"), "single window must not switch");
        let mut final_room = None;
        for _ in 0..8 {
            now += 2000;
            feed(&mut t, now, [-85.0, -70.0, -55.0], &th);
            final_room = t.step(now, &m, &g, &th, &scanning).room_id;
        }
        assert_eq!(final_room.as_deref(), Some("kitchen"));
    }

    #[test]
    fn boundary_noise_is_ambiguous_not_flapping() {
        let th = LocationThresholds::default();
        let (g, m) = (graph(), model());
        let scanning: BTreeSet<String> = g.node_room.keys().cloned().collect();
        let mut t = DeviceTracker::new("p");
        let mut rooms = Vec::new();
        for i in 0..30i64 {
            let jitter = if i % 2 == 0 { 3.0 } else { -3.0 };
            feed(&mut t, i * 2000, [-62.0 + jitter, -62.0 - jitter, -80.0], &th);
            rooms.push(t.step(i * 2000, &m, &g, &th, &scanning).room_id);
        }
        let switches = rooms.windows(2).filter(|w| w[0] != w[1] && w[0].is_some() && w[1].is_some()).count();
        assert!(switches <= 1, "flapping: {rooms:?}");
    }

    #[test]
    fn stale_then_not_observed() {
        let th = LocationThresholds::default();
        let (g, m) = (graph(), model());
        let scanning = BTreeSet::new();
        let mut t = DeviceTracker::new("p");
        feed(&mut t, 0, [-55.0, -70.0, -85.0], &th);
        t.step(0, &m, &g, &th, &scanning);
        assert_eq!(t.step(th.stale_ms + 1, &m, &g, &th, &scanning).state, LocationState::Stale);
        let e = t.step(th.not_observed_ms + 1, &m, &g, &th, &scanning);
        assert_eq!(e.state, LocationState::NotObserved);
        assert_eq!(e.room_id, None);
    }

    #[test]
    fn uncalibrated_fallback_labels_itself() {
        let th = LocationThresholds::default();
        let g = graph();
        let m = RoomModel::default();
        let mut t = DeviceTracker::new("p");
        let mut e = None;
        for i in 1..6 {
            feed(&mut t, i * 2000, [-50.0, -75.0, -90.0], &th);
            e = Some(t.step(i * 2000, &m, &g, &th, &BTreeSet::new()));
        }
        let e = e.unwrap();
        assert!(!e.calibrated);
        assert!(e.reason.contains("uncalibrated"));
    }

    #[test]
    fn probabilities_normalize() {
        let mut m: BTreeMap<String, f64> = [("a".to_string(), -1000.0), ("b".to_string(), -1001.0)].into_iter().collect();
        log_normalize(&mut m);
        let s: f64 = m.values().sum();
        assert!((s - 1.0).abs() < 1e-9);
    }

    #[test]
    fn evaluation_counts_unknown_as_incorrect() {
        let e = evaluate(&[("a".into(), Some("a".into())), ("a".into(), None), ("b".into(), Some("a".into()))]);
        assert!((e.accuracy - 1.0 / 3.0).abs() < 1e-9);
        assert!((e.coverage - 2.0 / 3.0).abs() < 1e-9);
        assert!((e.accepted_accuracy - 0.5).abs() < 1e-9);
    }
}
