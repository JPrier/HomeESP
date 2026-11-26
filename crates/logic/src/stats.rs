//! Windowed probe statistics and mergeable histograms.
//!
//! Loss = timeouts / eligible attempts (explicit denominator; skipped/unsupported
//! never count). Jitter = mean absolute RTT difference of consecutive successful
//! probes, not bridged across gaps. Percentiles over small samples are reported with
//! their sample count so callers can refuse to over-claim (spec §9.2).

use ho_domain::{Outcome, UnixMs};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Fixed log-spaced RTT histogram (microseconds). Mergeable across windows, so
/// rollups never average percentiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogHistogram {
    pub counts: Vec<u32>,
}

/// Bucket upper bounds in microseconds: ~12% relative resolution from 50 us to 60 s.
pub fn bucket_bounds() -> &'static [u32] {
    static B: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();
    B.get_or_init(|| {
        let mut v = Vec::new();
        let mut x = 50.0f64;
        while x < 60_000_000.0 {
            v.push(x.round() as u32);
            x *= 1.12;
        }
        v.push(u32::MAX);
        v
    })
}

impl Default for LogHistogram {
    fn default() -> Self {
        Self { counts: vec![0; bucket_bounds().len()] }
    }
}

impl LogHistogram {
    pub fn add(&mut self, rtt_us: u32) {
        let b = bucket_bounds();
        let i = b.partition_point(|ub| *ub < rtt_us).min(b.len() - 1);
        if let Some(c) = self.counts.get_mut(i) {
            *c = c.saturating_add(1);
        }
    }
    pub fn merge(&mut self, o: &LogHistogram) {
        for (a, b) in self.counts.iter_mut().zip(&o.counts) {
            *a = a.saturating_add(*b);
        }
    }
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|c| u64::from(*c)).sum()
    }
    /// Quantile estimate (bucket upper bound), `None` when empty.
    pub fn quantile(&self, q: f64) -> Option<u32> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        let rank = ((q.clamp(0.0, 1.0) * total as f64).ceil() as u64).max(1);
        let mut acc = 0u64;
        for (c, ub) in self.counts.iter().zip(bucket_bounds()) {
            acc += u64::from(*c);
            if acc >= rank {
                return Some(*ub);
            }
        }
        bucket_bounds().last().copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Sample {
    t: UnixMs,
    outcome: Outcome,
    rtt_us: Option<u32>,
    dns_good: Option<bool>,
}

/// Summary of a probe window. All rates carry their denominators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WindowStats {
    pub samples: u32,
    pub eligible: u32,
    pub successes: u32,
    pub timeouts: u32,
    pub other_failures: u32,
    pub skipped: u32,
    pub loss_pct: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub dns_bad: u32,
    pub scan_overlap: u32,
}

/// Rolling time window of probe results for one (vantage, target).
#[derive(Debug, Clone)]
pub struct ProbeWindow {
    window_ms: i64,
    max_samples: usize,
    gap_ms: i64,
    samples: VecDeque<Sample>,
    overlaps: VecDeque<UnixMs>,
}

impl ProbeWindow {
    pub fn new(window_ms: i64) -> Self {
        Self { window_ms, max_samples: 4096, gap_ms: 30_000, samples: VecDeque::new(), overlaps: VecDeque::new() }
    }

    /// Insert keeping time order (late samples are placed correctly).
    pub fn push(&mut self, t: UnixMs, outcome: Outcome, rtt_us: Option<u32>, dns_good: Option<bool>, overlap: bool) {
        let s = Sample { t, outcome, rtt_us, dns_good };
        let pos = self.samples.partition_point(|x| x.t <= t);
        self.samples.insert(pos, s);
        if overlap {
            self.overlaps.push_back(t);
        }
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    pub fn evict(&mut self, now: UnixMs) {
        let cutoff = now - self.window_ms;
        while self.samples.front().is_some_and(|s| s.t < cutoff) {
            self.samples.pop_front();
        }
        while self.overlaps.front().is_some_and(|t| *t < cutoff) {
            self.overlaps.pop_front();
        }
    }

    pub fn last_time(&self) -> Option<UnixMs> {
        self.samples.back().map(|s| s.t)
    }

    /// Typical spacing between samples (median), used for staleness.
    pub fn typical_interval_ms(&self) -> Option<i64> {
        if self.samples.len() < 3 {
            return None;
        }
        let mut d: Vec<i64> = self.samples.iter().zip(self.samples.iter().skip(1)).map(|(a, b)| b.t - a.t).collect();
        d.sort_unstable();
        d.get(d.len() / 2).copied()
    }

    pub fn stats(&self) -> WindowStats {
        let mut s = WindowStats { samples: self.samples.len() as u32, ..Default::default() };
        let mut rtts: Vec<u32> = Vec::new();
        let mut jitter_sum = 0f64;
        let mut jitter_n = 0u32;
        let mut prev: Option<(UnixMs, u32)> = None;
        for x in &self.samples {
            if x.outcome.is_eligible() {
                s.eligible += 1;
            } else {
                s.skipped += 1;
            }
            match x.outcome {
                Outcome::Success => s.successes += 1,
                Outcome::Timeout => s.timeouts += 1,
                o if o.is_failure() => s.other_failures += 1,
                _ => {}
            }
            if x.dns_good == Some(false) {
                s.dns_bad += 1;
            }
            if let (Outcome::Success, Some(r)) = (x.outcome, x.rtt_us) {
                rtts.push(r);
                if let Some((pt, pr)) = prev {
                    if x.t - pt <= self.gap_ms {
                        jitter_sum += (f64::from(r) - f64::from(pr)).abs();
                        jitter_n += 1;
                    }
                }
                prev = Some((x.t, r));
            } else if x.outcome.is_eligible() {
                prev = None; // do not bridge failures
            }
        }
        s.scan_overlap = self.overlaps.len() as u32;
        if s.eligible > 0 {
            s.loss_pct = Some(f64::from(s.timeouts) * 100.0 / f64::from(s.eligible));
        }
        if !rtts.is_empty() {
            rtts.sort_unstable();
            let q = |p: f64| {
                let idx = ((p * rtts.len() as f64).ceil() as usize).saturating_sub(1).min(rtts.len() - 1);
                rtts.get(idx).map(|v| f64::from(*v) / 1000.0)
            };
            s.p50_ms = q(0.50);
            s.p95_ms = q(0.95);
            s.p99_ms = if rtts.len() >= 100 { q(0.99) } else { None }; // no p99 claims from tiny samples
        }
        if jitter_n > 0 {
            s.jitter_ms = Some(jitter_sum / f64::from(jitter_n) / 1000.0);
        }
        s
    }
}

/// Robust baseline: median and MAD with a minimum scale.
pub fn median_mad(values: &[f64]) -> Option<(f64, f64)> {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let med = *v.get(v.len() / 2)?;
    let mut dev: Vec<f64> = v.iter().map(|x| (x - med).abs()).collect();
    dev.sort_by(f64::total_cmp);
    let mad = *dev.get(dev.len() / 2)?;
    Some((med, mad))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn loss_jitter_and_percentiles() {
        let mut w = ProbeWindow::new(300_000);
        for i in 0..40i64 {
            let ok = i % 10 != 0;
            w.push(i * 5000, if ok { Outcome::Success } else { Outcome::Timeout }, ok.then_some(2000 + (i as u32 % 3) * 1000), None, false);
        }
        w.push(41 * 5000, Outcome::SkippedDeferred, None, None, false);
        let s = w.stats();
        assert_eq!(s.eligible, 40);
        assert_eq!(s.timeouts, 4);
        assert_eq!(s.skipped, 1);
        assert!((s.loss_pct.unwrap() - 10.0).abs() < 1e-9);
        assert!(s.p95_ms.unwrap() >= 3.9 && s.p95_ms.unwrap() <= 4.0);
        assert!(s.p99_ms.is_none(), "no p99 from 36 samples");
        assert!(s.jitter_ms.unwrap() > 0.0);
        w.evict(41 * 5000 + 300_000);
        assert_eq!(w.stats().samples, 1);
    }

    #[test]
    fn empty_window_reports_none_not_zero() {
        let w = ProbeWindow::new(1000);
        let s = w.stats();
        assert_eq!(s.loss_pct, None);
        assert_eq!(s.p95_ms, None);
    }

    #[test]
    fn histogram_quantiles_and_merge() {
        let mut h = LogHistogram::default();
        for v in 1..=100u32 {
            h.add(v * 1000);
        }
        let p50 = h.quantile(0.5).unwrap();
        assert!((45_000..=60_000).contains(&p50), "{p50}");
        let mut h2 = LogHistogram::default();
        h2.merge(&h);
        h2.merge(&h);
        assert_eq!(h2.total(), 200);
        assert_eq!(h2.quantile(0.5), h.quantile(0.5));
        assert_eq!(LogHistogram::default().quantile(0.5), None);
    }

    proptest! {
        #[test]
        fn loss_in_bounds_and_late_inserts_sorted(ts in proptest::collection::vec((0i64..100_000, any::<bool>()), 1..200)) {
            let mut w = ProbeWindow::new(1_000_000);
            for (t, ok) in &ts {
                w.push(*t, if *ok { Outcome::Success } else { Outcome::Timeout }, ok.then_some(1000), None, false);
            }
            let s = w.stats();
            let l = s.loss_pct.unwrap();
            prop_assert!((0.0..=100.0).contains(&l));
            prop_assert!(w.samples.iter().zip(w.samples.iter().skip(1)).all(|(a, b)| a.t <= b.t));
        }
    }
}
