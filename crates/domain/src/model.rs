//! Normalized observations (what was measured, with provenance and uncertainty) and
//! derived-state vocabularies (what we concluded). The two are never mixed: derived
//! states always point back at evidence.

use crate::UnixMs;
use serde::{Deserialize, Serialize};

/// Where an observation came from. `(node_id, boot_id, sequence, index)` is unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Provenance {
    /// Node id, or `central` for the wired server vantage.
    pub source: String,
    pub boot_id: String,
    pub sequence: u64,
    pub index: u16,
}

/// Event-time estimate: server-estimated UTC of the sample plus uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTime {
    pub observed_at: UnixMs,
    pub uncertainty_ms: u32,
    pub received_at: UnixMs,
}

/// Normalized probe outcome classes (spec §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Timeout,
    RefusedUnreachable,
    InvalidResponse,
    ConfigError,
    Unsupported,
    Canceled,
    SkippedDeferred,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::RefusedUnreachable => "refused_unreachable",
            Self::InvalidResponse => "invalid_response",
            Self::ConfigError => "config_error",
            Self::Unsupported => "unsupported",
            Self::Canceled => "canceled",
            Self::SkippedDeferred => "skipped_deferred",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "success" => Self::Success,
            "timeout" => Self::Timeout,
            "refused_unreachable" => Self::RefusedUnreachable,
            "invalid_response" => Self::InvalidResponse,
            "config_error" => Self::ConfigError,
            "unsupported" => Self::Unsupported,
            "canceled" => Self::Canceled,
            "skipped_deferred" => Self::SkippedDeferred,
            _ => return None,
        })
    }
    /// Counts in the loss denominator (an attempt actually made).
    pub fn is_eligible(self) -> bool {
        matches!(self, Self::Success | Self::Timeout | Self::RefusedUnreachable | Self::InvalidResponse)
    }
    /// A failed attempt for health purposes.
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Timeout | Self::RefusedUnreachable | Self::InvalidResponse)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsInfo {
    pub rcode: u8,
    /// `match`, `mismatch`, `expected_nxdomain`, `unexpected_nxdomain`, `no_answer`,
    /// `servfail`, `refused`, `malformed`, `n/a`.
    pub answer: String,
    pub transport: String,
    pub qtype: u16,
}

impl DnsInfo {
    pub fn is_good(&self) -> bool {
        self.answer == "match" || self.answer == "expected_nxdomain"
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeObs {
    pub target_id: String,
    pub kind: String,
    pub outcome: Outcome,
    /// RTT in microseconds; `None` unless `outcome == Success`. Never zero-for-failure.
    pub rtt_us: Option<u32>,
    pub scan_overlap: bool,
    pub dscp: u8,
    pub sched_late_ms: u16,
    pub error_code: i16,
    pub dns: Option<DnsInfo>,
    /// BSSID the node was associated with when the probe ran (if known).
    pub via_bssid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiObs {
    pub status: String,
    pub rssi_dbm: Option<i8>,
    pub channel: u8,
    pub bssid: Option<String>,
    pub assoc_gen: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApSample {
    pub bssid: String,
    pub channel: u8,
    pub rssi_dbm: i8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApScanObs {
    pub scan_id: u16,
    pub duration_ms: u16,
    pub completeness: String,
    pub channel_counts: Vec<u8>,
    pub samples: Vec<ApSample>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleObs {
    pub event: String,
    pub reason: u16,
    pub prior_bssid: Option<String>,
    pub new_bssid: Option<String>,
    pub duration_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemObs {
    pub uptime_s: u32,
    pub heap_free: u32,
    pub heap_min: u32,
    pub heap_max_block: u32,
    pub heap_frag_pct: u8,
    pub reset_reason: u8,
    pub queue_fill_pct: u8,
    pub drops_overflow: u16,
    pub drops_budget: u16,
    pub drops_expired: u16,
    pub missed_schedules: u16,
    pub loop_lag_max_ms: u16,
    pub reconnects: u16,
    pub tx_bytes: u32,
    pub tx_frames: u32,
    pub fw_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BleObs {
    pub device_id: String,
    pub window_ms: u16,
    pub count: u16,
    pub rssi_min: i8,
    pub rssi_max: i8,
    pub rssi_mean: f64,
    pub last_seen_age_ms: u16,
    pub coverage_permille: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorObs {
    pub sensor_id: String,
    pub kind: u8,
    pub unit: u8,
    pub value: f64,
    pub quality: u8,
    pub calibration_rev: u16,
}

/// One normalized observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObsKind {
    Probe(ProbeObs),
    Wifi(WifiObs),
    ApScan(ApScanObs),
    Lifecycle(LifecycleObs),
    System(SystemObs),
    Ble(BleObs),
    Sensor(SensorObs),
    Heartbeat { uptime_s: u32 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub prov: Provenance,
    pub time: EventTime,
    pub kind: ObsKind,
}

/// Health of an asset / target / vantage (spec §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Unknown,
    Healthy,
    Degraded,
    Failed,
    Recovering,
    Maintenance,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Recovering => "recovering",
            Self::Maintenance => "maintenance",
        }
    }
    pub fn is_bad(self) -> bool {
        matches!(self, Self::Degraded | Self::Failed)
    }
}

/// Node liveness as seen by the server (never "powered off": we cannot know that).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLiveness {
    Unknown,
    Online,
    Stale,
    Missing,
}

/// Location state of an enrolled device (spec §10.3 step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationState {
    Located,
    Ambiguous,
    Stale,
    NotObserved,
    Disabled,
}

/// Anonymous room occupancy (spec §10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Occupancy {
    Occupied,
    Vacant,
    Unknown,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn outcome_roundtrip_and_classes() {
        for o in [
            Outcome::Success,
            Outcome::Timeout,
            Outcome::RefusedUnreachable,
            Outcome::InvalidResponse,
            Outcome::ConfigError,
            Outcome::Unsupported,
            Outcome::Canceled,
            Outcome::SkippedDeferred,
        ] {
            assert_eq!(Outcome::parse(o.as_str()), Some(o));
        }
        assert!(!Outcome::SkippedDeferred.is_eligible(), "skips are not loss");
        assert!(Outcome::Timeout.is_failure());
        assert!(!Outcome::Unsupported.is_failure());
    }

    #[test]
    fn obs_serializes_with_type_tag() {
        let k = ObsKind::Heartbeat { uptime_s: 5 };
        let s = serde_json::to_string(&k).unwrap();
        assert!(s.contains("\"type\":\"heartbeat\""));
    }
}
