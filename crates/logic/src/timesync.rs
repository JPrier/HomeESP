//! Node-monotonic to UTC mapping (spec §8.4).
//!
//! For each frame, `received_at - sent_mono` = true offset + transit delay (>= 0).
//! The minimum over recent frames is the best (lowest-delay) offset estimate, so
//! estimated event times never land in the future. The estimate resets on a new
//! boot. Uncertainty grows with how noisy recent frames are, plus a drift allowance.

use ho_domain::UnixMs;
use std::collections::VecDeque;

/// Number of recent offset samples kept per boot.
const WINDOW: usize = 64;
/// Crystal drift allowance applied to sample age (100 ppm).
const DRIFT_PPM: i64 = 100;
/// Floor for reported uncertainty (MQTT + scheduling granularity).
const MIN_UNCERTAINTY_MS: i64 = 20;

#[derive(Debug, Clone, Default)]
pub struct OffsetEstimator {
    boot: Option<[u8; 16]>,
    samples: VecDeque<i64>,
    min: Option<i64>,
}

/// Result of mapping a sample into server time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapped {
    pub observed_at: UnixMs,
    pub uncertainty_ms: u32,
}

impl OffsetEstimator {
    /// Feed one frame. Returns `true` if this frame started a new boot epoch.
    pub fn observe(&mut self, boot: [u8; 16], sent_mono_ms: u64, received_at: UnixMs) -> bool {
        let new_boot = self.boot != Some(boot);
        if new_boot {
            self.boot = Some(boot);
            self.samples.clear();
            self.min = None;
        }
        let mono = i64::try_from(sent_mono_ms).unwrap_or(i64::MAX);
        let off = received_at.saturating_sub(mono);
        if self.samples.len() == WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(off);
        self.min = self.samples.iter().copied().min();
        new_boot
    }

    /// Spread between the median and minimum offset: a measure of transit jitter.
    pub fn spread_ms(&self) -> i64 {
        let Some(min) = self.min else { return i64::MAX };
        let mut v: Vec<i64> = self.samples.iter().copied().collect();
        v.sort_unstable();
        let med = v.get(v.len() / 2).copied().unwrap_or(min);
        med - min
    }

    /// Whether the estimate is good enough for cross-node fusion.
    pub fn is_precise(&self, max_spread_ms: i64) -> bool {
        self.samples.len() >= 3 && self.spread_ms() <= max_spread_ms
    }

    /// Map a node-monotonic sample time to UTC. `age_ms` is relative to `sent_mono`.
    pub fn map(&self, sent_mono_ms: u64, age_ms: u32, received_at: UnixMs) -> Mapped {
        let Some(min) = self.min else {
            return Mapped {
                observed_at: received_at.saturating_sub(i64::from(age_ms)),
                uncertainty_ms: u32::MAX,
            };
        };
        let mono = i64::try_from(sent_mono_ms).unwrap_or(i64::MAX);
        let sample_mono = mono.saturating_sub(i64::from(age_ms));
        let observed = sample_mono.saturating_add(min).min(received_at);
        let drift = i64::from(age_ms) * DRIFT_PPM / 1_000_000;
        let unc = (self.spread_ms() + drift).max(MIN_UNCERTAINTY_MS);
        Mapped { observed_at: observed, uncertainty_ms: u32::try_from(unc).unwrap_or(u32::MAX) }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn min_delay_estimate_and_boot_reset() {
        let mut e = OffsetEstimator::default();
        let base = 1_700_000_000_000i64;
        // node mono 1000 at true time base+1000; delays 50, 5, 30 ms
        assert!(e.observe([1; 16], 1000, base + 1000 + 50));
        assert!(!e.observe([1; 16], 3000, base + 3000 + 5));
        e.observe([1; 16], 5000, base + 5000 + 30);
        let m = e.map(5000, 200, base + 5030);
        assert_eq!(m.observed_at, base + 5000 - 200 + 5);
        assert!(m.uncertainty_ms >= 20);
        assert!(e.observe([2; 16], 10, base + 9000), "new boot resets");
        assert_eq!(e.map(10, 0, base + 9000).observed_at, base + 9000);
    }

    #[test]
    fn unsynced_mapping_is_explicitly_uncertain() {
        let e = OffsetEstimator::default();
        let m = e.map(100, 50, 10_000);
        assert_eq!(m.uncertainty_ms, u32::MAX);
        assert_eq!(m.observed_at, 9_950);
    }

    proptest! {
        #[test]
        fn never_maps_into_the_future(delays in proptest::collection::vec(0i64..2000, 1..50), age in 0u32..100_000) {
            let mut e = OffsetEstimator::default();
            let base = 1_000_000_000i64;
            let mut last = (0u64, 0i64);
            for (i, d) in delays.iter().enumerate() {
                let mono = (i as u64 + 1) * 2000;
                let recv = base + mono as i64 + d;
                e.observe([9; 16], mono, recv);
                last = (mono, recv);
            }
            let m = e.map(last.0, age, last.1);
            prop_assert!(m.observed_at <= last.1);
        }
    }
}
