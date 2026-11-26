//! Per-(node, boot) sequence tracking: duplicate suppression and bounded gap
//! detection. A gap is only declared once it falls behind the reordering window;
//! gaps are *missing reports*, never inferred probe loss (spec §8.4).

use std::collections::BTreeSet;

/// Sequences that can arrive out of order before a gap is declared.
pub const REORDER_WINDOW: u64 = 64;
/// A forward jump larger than this is treated as an anomaly (tracking restarts)
/// rather than as millions of missing reports.
pub const MAX_FORWARD_JUMP: u64 = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqVerdict {
    /// First time we see this sequence.
    New,
    /// Already processed (QoS 1 redelivery, replay).
    Duplicate,
    /// Older than anything we still track; treated as historical (not current state).
    Late,
}

#[derive(Debug, Clone, Default)]
pub struct SeqTracker {
    boot: Option<[u8; 16]>,
    highest: Option<u64>,
    seen: BTreeSet<u64>,
    /// Confirmed missing sequence numbers (fell out of the reorder window unseen).
    pub gaps: u64,
    pub duplicates: u64,
    /// Implausible forward jumps (counted, not converted into gaps).
    pub jumps: u64,
}

impl SeqTracker {
    pub fn observe(&mut self, boot: [u8; 16], seq: u64) -> SeqVerdict {
        if self.boot != Some(boot) {
            self.boot = Some(boot);
            self.highest = None;
            self.seen.clear();
        }
        let Some(high) = self.highest else {
            self.highest = Some(seq);
            self.seen.insert(seq);
            return SeqVerdict::New;
        };
        let floor = high.saturating_sub(REORDER_WINDOW);
        if seq < floor {
            return SeqVerdict::Late;
        }
        if !self.seen.insert(seq) {
            self.duplicates += 1;
            return SeqVerdict::Duplicate;
        }
        if seq > high {
            if seq - high > MAX_FORWARD_JUMP {
                self.jumps += 1;
                self.highest = Some(seq);
                self.seen.clear();
                self.seen.insert(seq);
                return SeqVerdict::New;
            }
            self.highest = Some(seq);
            let new_floor = seq.saturating_sub(REORDER_WINDOW);
            // Count sequences leaving the window unseen as gaps (arithmetically, O(window)).
            let lo = floor.max(self.seen.first().copied().unwrap_or(floor));
            if new_floor > lo {
                let seen_in = self.seen.range(lo..new_floor).count() as u64;
                self.gaps += (new_floor - lo).saturating_sub(seen_in);
            }
            self.seen = self.seen.split_off(&new_floor);
        }
        SeqVerdict::New
    }

    pub fn highest(&self) -> Option<u64> {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn duplicates_reorder_and_gaps() {
        let mut t = SeqTracker::default();
        let b = [1; 16];
        assert_eq!(t.observe(b, 1), SeqVerdict::New);
        assert_eq!(t.observe(b, 3), SeqVerdict::New);
        assert_eq!(t.observe(b, 2), SeqVerdict::New, "reordered within window");
        assert_eq!(t.observe(b, 2), SeqVerdict::Duplicate);
        assert_eq!(t.gaps, 0);
        // Skip 4..=9, then advance far enough that they leave the window.
        t.observe(b, 10);
        t.observe(b, 10 + REORDER_WINDOW + 1);
        assert_eq!(t.gaps, 6, "4..=9 never arrived");
        assert_eq!(t.observe(b, 1), SeqVerdict::Late);
        // New boot resets.
        assert_eq!(t.observe([2; 16], 1), SeqVerdict::New);
        // A hostile jump to u64::MAX is an anomaly, not 2^64 gaps (and returns quickly).
        let g = t.gaps;
        assert_eq!(t.observe([2; 16], u64::MAX), SeqVerdict::New);
        assert_eq!(t.gaps, g);
        assert_eq!(t.jumps, 1);
    }

    proptest! {
        #[test]
        fn redelivery_is_always_duplicate(seqs in proptest::collection::vec(0u64..200, 1..200)) {
            let mut t = SeqTracker::default();
            let b = [3; 16];
            for s in &seqs {
                if t.observe(b, *s) == SeqVerdict::New {
                    prop_assert_eq!(t.observe(b, *s), SeqVerdict::Duplicate);
                }
            }
        }
    }
}
