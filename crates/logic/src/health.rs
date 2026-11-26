//! Per-(vantage, target) health state machine and node liveness (spec §12.2).
//!
//! Every transition records *why* (a reason string with the numbers that triggered
//! it) so incidents can cite evidence. Thresholds come from configuration.

use crate::stats::{ProbeWindow, WindowStats};
use ho_domain::{Health, NodeLiveness, Outcome, Thresholds, UnixMs};
use serde::Serialize;

/// Health tracker for one probe target from one vantage.
#[derive(Debug, Clone)]
pub struct TargetHealth {
    pub window: ProbeWindow,
    pub health: Health,
    pub reason: String,
    pub since: UnixMs,
    consecutive_fail: u32,
    consecutive_ok: u32,
    recovering_since: Option<UnixMs>,
    last_current: UnixMs,
    /// Robust baseline p95 (ms) when known (from history); used for relative latency.
    pub baseline_p95_ms: Option<f64>,
    pub is_dns: bool,
}

/// A health transition worth reporting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HealthChange {
    pub from: Health,
    pub to: Health,
    pub reason: String,
}

impl TargetHealth {
    pub fn new(window_ms: i64, is_dns: bool) -> Self {
        Self {
            window: ProbeWindow::new(window_ms),
            health: Health::Unknown,
            reason: "no data yet".into(),
            since: 0,
            consecutive_fail: 0,
            consecutive_ok: 0,
            recovering_since: None,
            last_current: i64::MIN,
            baseline_p95_ms: None,
            is_dns,
        }
    }

    /// Record a result. Late samples (older than the newest seen) update the window
    /// for history but do not move consecutive counters (current state never regresses).
    pub fn record(
        &mut self,
        t: UnixMs,
        outcome: Outcome,
        rtt_us: Option<u32>,
        dns_good: Option<bool>,
        overlap: bool,
        th: &Thresholds,
    ) -> Option<HealthChange> {
        self.window.push(t, outcome, rtt_us, dns_good, overlap);
        if t < self.last_current {
            return None;
        }
        self.last_current = t;
        if !outcome.is_eligible() {
            return None; // skipped/unsupported/config errors are not evidence of path health
        }
        let failed = outcome.is_failure() || dns_good == Some(false);
        if failed {
            self.consecutive_fail += 1;
            self.consecutive_ok = 0;
        } else {
            self.consecutive_ok += 1;
            self.consecutive_fail = 0;
        }
        self.evaluate(t, th)
    }

    /// Re-evaluate (also called on ticks for staleness and recovery timers).
    pub fn evaluate(&mut self, now: UnixMs, th: &Thresholds) -> Option<HealthChange> {
        self.window.evict(now);
        let s = self.window.stats();
        let stale_after = self.window.typical_interval_ms().map(|i| (i * 4).max(30_000)).unwrap_or(60_000);
        let stale = self.window.last_time().is_none_or(|t| now - t > stale_after);
        let (next, why) = if stale {
            (Health::Unknown, format!("no fresh results for {}s", stale_after / 1000))
        } else {
            self.classify(now, &s, th)
        };
        self.transition(now, next, why)
    }

    fn classify(&mut self, now: UnixMs, s: &WindowStats, th: &Thresholds) -> (Health, String) {
        if self.consecutive_fail >= th.critical_consecutive_failures {
            self.recovering_since = None;
            return (Health::Failed, format!("{} consecutive failed checks", self.consecutive_fail));
        }
        let degraded = self.degraded_reason(s, th);
        let was_bad = matches!(self.health, Health::Failed | Health::Degraded | Health::Recovering);
        if was_bad {
            if self.consecutive_ok >= th.recovery_consecutive_successes && degraded.is_none() {
                let since = *self.recovering_since.get_or_insert(now);
                if now - since >= th.recovery_stable_ms {
                    self.recovering_since = None;
                    return (Health::Healthy, "recovered: sustained successful checks".into());
                }
                return (Health::Recovering, format!("{} consecutive successes; confirming stability", self.consecutive_ok));
            }
            if let Some(d) = degraded {
                self.recovering_since = None;
                return (Health::Degraded, d);
            }
            if self.health == Health::Failed {
                return (Health::Failed, self.reason.clone());
            }
            self.recovering_since = None;
            return (Health::Recovering, "awaiting consecutive successes".into());
        }
        match degraded {
            Some(d) => (Health::Degraded, d),
            None if s.successes > 0 => (Health::Healthy, "checks succeeding".into()),
            None => (self.health, self.reason.clone()),
        }
    }

    fn degraded_reason(&self, s: &WindowStats, th: &Thresholds) -> Option<String> {
        if s.eligible >= th.loss_min_samples {
            if let Some(l) = s.loss_pct {
                if l > th.loss_degraded_pct {
                    return Some(format!("loss {l:.1}% over {} eligible probes", s.eligible));
                }
            }
        }
        if s.successes >= th.latency_min_samples {
            if let Some(p95) = s.p95_ms {
                let over_abs = p95 > th.latency_p95_abs_ms;
                let over_rel = self.baseline_p95_ms.is_none_or(|b| p95 > b * th.latency_baseline_multiple);
                if over_abs && over_rel {
                    return Some(format!("p95 {p95:.1} ms over {} samples", s.successes));
                }
            }
        }
        if self.is_dns && s.dns_bad >= th.dns_failures_degraded {
            return Some(format!("{} DNS answers invalid/failed in window", s.dns_bad));
        }
        None
    }

    fn transition(&mut self, now: UnixMs, next: Health, why: String) -> Option<HealthChange> {
        if self.health == Health::Maintenance {
            return None;
        }
        if next == self.health {
            self.reason = why;
            return None;
        }
        let ch = HealthChange { from: self.health, to: next, reason: why.clone() };
        self.health = next;
        self.reason = why;
        self.since = now;
        Some(ch)
    }

    pub fn stats(&self) -> WindowStats {
        self.window.stats()
    }

    pub fn set_maintenance(&mut self, on: bool, now: UnixMs) {
        if on {
            self.health = Health::Maintenance;
            self.reason = "maintenance window".into();
        } else if self.health == Health::Maintenance {
            self.health = Health::Unknown;
            self.reason = "maintenance ended".into();
        }
        self.since = now;
    }
}

/// Liveness from the freshest authenticated frame (spec §8.1: retained status alone
/// is not proof). `Missing` means "no fresh data", never "powered off".
pub fn liveness(last_seen: Option<UnixMs>, now: UnixMs, missing_ms: i64, ingestion_ok: bool) -> NodeLiveness {
    if !ingestion_ok {
        return NodeLiveness::Unknown;
    }
    match last_seen {
        None => NodeLiveness::Unknown,
        Some(t) if now - t <= missing_ms / 2 => NodeLiveness::Online,
        Some(t) if now - t <= missing_ms => NodeLiveness::Stale,
        Some(_) => NodeLiveness::Missing,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn th() -> Thresholds {
        Thresholds::default()
    }

    #[test]
    fn three_failures_fail_then_recover_after_stable_period() {
        let t = th();
        let mut h = TargetHealth::new(300_000, false);
        let mut now = 0;
        for _ in 0..5 {
            now += 5000;
            h.record(now, Outcome::Success, Some(1000), None, false, &t);
        }
        assert_eq!(h.health, Health::Healthy);
        for i in 0..3 {
            now += 5000;
            let ch = h.record(now, Outcome::Timeout, None, None, false, &t);
            if i < 2 {
                assert_eq!(h.health, Health::Healthy);
            } else {
                assert_eq!(ch.unwrap().to, Health::Failed);
            }
        }
        // 15 s failure detection at 5 s cadence (<= 30 s target).
        for _ in 0..3 {
            now += 5000;
            h.record(now, Outcome::Success, Some(1000), None, false, &t);
        }
        assert_eq!(h.health, Health::Recovering);
        for _ in 0..3 {
            now += 5000;
            h.record(now, Outcome::Success, Some(1000), None, false, &t);
        }
        // Loss in the 5-min window (3/14 ~ 21%) is below min-sample count, so no degrade.
        assert_eq!(h.health, Health::Healthy, "{}", h.reason);
    }

    #[test]
    fn skipped_probes_never_count_as_failures() {
        let t = th();
        let mut h = TargetHealth::new(300_000, false);
        for i in 0..10 {
            h.record(i * 1000, Outcome::SkippedDeferred, None, None, true, &t);
        }
        assert_eq!(h.health, Health::Unknown);
    }

    #[test]
    fn loss_degrades_with_enough_samples() {
        let t = th();
        let mut h = TargetHealth::new(300_000, false);
        for i in 0..40i64 {
            let ok = i % 8 != 0; // 12.5% loss, never 3 in a row
            h.record(i * 5000, if ok { Outcome::Success } else { Outcome::Timeout }, ok.then_some(900), None, false, &t);
        }
        assert_eq!(h.health, Health::Degraded, "{}", h.reason);
        assert!(h.reason.contains("loss"));
    }

    #[test]
    fn late_sample_does_not_regress_current_state() {
        let t = th();
        let mut h = TargetHealth::new(300_000, false);
        for i in 1..=5 {
            h.record(i * 5000, Outcome::Success, Some(500), None, false, &t);
        }
        for _ in 0..5 {
            assert!(h.record(1000, Outcome::Timeout, None, None, false, &t).is_none());
        }
        assert_eq!(h.health, Health::Healthy);
    }

    #[test]
    fn staleness_becomes_unknown_not_failed() {
        let t = th();
        let mut h = TargetHealth::new(300_000, false);
        for i in 1..=5 {
            h.record(i * 5000, Outcome::Success, Some(500), None, false, &t);
        }
        let ch = h.evaluate(25_000 + 120_000, &t).unwrap();
        assert_eq!(ch.to, Health::Unknown);
    }

    #[test]
    fn dns_wrong_answers_fail() {
        let t = th();
        let mut h = TargetHealth::new(300_000, true);
        for i in 1..=4 {
            h.record(i * 30_000, Outcome::Success, Some(2000), Some(false), false, &t);
        }
        assert_eq!(h.health, Health::Failed);
    }

    #[test]
    fn liveness_rules() {
        assert_eq!(liveness(Some(0), 10_000, 30_000, true), NodeLiveness::Online);
        assert_eq!(liveness(Some(0), 20_000, 30_000, true), NodeLiveness::Stale);
        assert_eq!(liveness(Some(0), 31_000, 30_000, true), NodeLiveness::Missing);
        assert_eq!(liveness(Some(0), 31_000, 30_000, false), NodeLiveness::Unknown);
        assert_eq!(liveness(None, 31_000, 30_000, true), NodeLiveness::Unknown);
    }
}
