//! Decoded wire frames -> normalized observations with provenance and event time.

use crate::timesync::OffsetEstimator;
use ho_domain::*;
use ho_protocol as p;

/// Hex-encode a boot id for storage/provenance.
pub fn boot_hex(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn mac(m: &[u8; 6]) -> String {
    format_mac(m)
}

fn outcome(o: p::ProbeOutcome) -> Outcome {
    match o {
        p::ProbeOutcome::Success => Outcome::Success,
        p::ProbeOutcome::Timeout => Outcome::Timeout,
        p::ProbeOutcome::RefusedUnreachable => Outcome::RefusedUnreachable,
        p::ProbeOutcome::InvalidResponse => Outcome::InvalidResponse,
        p::ProbeOutcome::ConfigError => Outcome::ConfigError,
        p::ProbeOutcome::Unsupported => Outcome::Unsupported,
        p::ProbeOutcome::Canceled => Outcome::Canceled,
        p::ProbeOutcome::SkippedDeferred => Outcome::SkippedDeferred,
    }
}

fn link_status(s: p::LinkStatus) -> &'static str {
    match s {
        p::LinkStatus::Unknown => "unknown",
        p::LinkStatus::Connected => "connected",
        p::LinkStatus::Connecting => "connecting",
        p::LinkStatus::Disconnected => "disconnected",
        p::LinkStatus::NoApFound => "no_ap_found",
        p::LinkStatus::AuthFailed => "auth_failed",
    }
}

/// Context needed to normalize one frame.
pub struct FrameCtx<'a> {
    pub received_at: UnixMs,
    pub clock: &'a OffsetEstimator,
    /// BSSID the node reported most recently (attached to probes as `via_bssid`).
    pub current_bssid: Option<String>,
}

/// Convert every understood record into an observation. Unknown records and
/// server->node record types are skipped. Returns observations in record order.
pub fn normalize(frame: &p::Frame<'_>, ctx: &FrameCtx<'_>) -> Vec<Observation> {
    let h = &frame.header;
    let boot = boot_hex(&h.boot_id);
    let mut out = Vec::new();
    let mut via = ctx.current_bssid.clone();
    for (i, rec) in frame.records().enumerate() {
        let index = u16::try_from(i).unwrap_or(u16::MAX);
        let mk = |age: u32, kind: ObsKind| {
            let m = ctx.clock.map(h.sent_mono_ms, age, ctx.received_at);
            Observation {
                prov: Provenance { source: h.node_id.to_string(), boot_id: boot.clone(), sequence: h.sequence, index },
                time: EventTime { observed_at: m.observed_at, uncertainty_ms: m.uncertainty_ms, received_at: ctx.received_at },
                kind,
            }
        };
        let obs = match rec {
            p::Record::WifiLink(w) => {
                if let Some(b) = w.bssid {
                    via = Some(mac(&b));
                }
                mk(
                    w.age_ms,
                    ObsKind::Wifi(WifiObs {
                        status: link_status(w.status).into(),
                        rssi_dbm: w.rssi_dbm,
                        channel: w.channel,
                        bssid: w.bssid.as_ref().map(mac),
                        assoc_gen: w.assoc_gen,
                    }),
                )
            }
            p::Record::Probe(pr) => mk(
                pr.age_ms,
                ObsKind::Probe(ProbeObs {
                    target_id: pr.target_id.to_string(),
                    kind: pr.kind.as_str().into(),
                    outcome: outcome(pr.outcome),
                    rtt_us: pr.rtt_us,
                    scan_overlap: pr.scan_overlap,
                    dscp: pr.dscp,
                    sched_late_ms: pr.sched_late_ms,
                    error_code: pr.error_code,
                    dns: pr.dns.map(|d| DnsInfo {
                        rcode: d.rcode,
                        answer: d.answer.as_str().into(),
                        transport: if d.transport == 1 { "tcp".into() } else { "udp".into() },
                        qtype: d.qtype,
                    }),
                    via_bssid: via.clone(),
                }),
            ),
            p::Record::ApScan(s) => mk(
                s.age_ms,
                ObsKind::ApScan(ApScanObs {
                    scan_id: s.scan_id,
                    duration_ms: s.duration_ms,
                    completeness: match s.completeness {
                        p::ScanCompleteness::Complete => "complete",
                        p::ScanCompleteness::Partial => "partial",
                        p::ScanCompleteness::Skipped => "skipped",
                    }
                    .into(),
                    channel_counts: s.channel_counts.to_vec(),
                    samples: s
                        .entries
                        .iter()
                        .map(|e| ApSample { bssid: mac(&e.bssid), channel: e.channel, rssi_dbm: e.rssi_dbm })
                        .collect(),
                }),
            ),
            p::Record::Lifecycle(l) => mk(
                l.age_ms,
                ObsKind::Lifecycle(LifecycleObs {
                    event: l.event.as_str().into(),
                    reason: l.reason,
                    prior_bssid: l.prior_bssid.as_ref().map(mac),
                    new_bssid: l.new_bssid.as_ref().map(mac),
                    duration_ms: l.duration_ms,
                }),
            ),
            p::Record::System(s) => mk(
                s.age_ms,
                ObsKind::System(SystemObs {
                    uptime_s: s.uptime_s,
                    heap_free: s.heap_free,
                    heap_min: s.heap_min,
                    heap_max_block: s.heap_max_block,
                    heap_frag_pct: s.heap_frag_pct,
                    reset_reason: s.reset_reason,
                    queue_fill_pct: s.queue_fill_pct,
                    drops_overflow: s.drops_overflow,
                    drops_budget: s.drops_budget,
                    drops_expired: s.drops_expired,
                    missed_schedules: s.missed_schedules,
                    loop_lag_max_ms: s.loop_lag_max_ms,
                    reconnects: s.reconnects,
                    tx_bytes: s.tx_bytes,
                    tx_frames: s.tx_frames,
                    fw_version: s.fw_version.into(),
                }),
            ),
            p::Record::Ble(b) => mk(
                b.age_ms,
                ObsKind::Ble(BleObs {
                    device_id: b.device_id.into(),
                    window_ms: b.window_ms,
                    count: b.count,
                    rssi_min: b.rssi_min,
                    rssi_max: b.rssi_max,
                    rssi_mean: f64::from(b.rssi_sum) / f64::from(b.count.max(1)),
                    last_seen_age_ms: b.last_seen_age_ms,
                    coverage_permille: b.coverage_permille,
                }),
            ),
            p::Record::Sensor(s) => mk(
                s.age_ms,
                ObsKind::Sensor(SensorObs {
                    sensor_id: s.sensor_id.into(),
                    kind: s.kind,
                    unit: s.unit,
                    value: f64::from(s.value_milli) / 1000.0,
                    quality: s.quality,
                    calibration_rev: s.calibration_rev,
                }),
            ),
            p::Record::NodeStatus(s) => mk(0, ObsKind::Heartbeat { uptime_s: s.uptime_s }),
            _ => continue,
        };
        out.push(obs);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_probe_and_link_with_provenance() {
        let mut buf = [0u8; 512];
        let h = p::Header {
            kind: p::MsgKind::Telemetry,
            flags: 0,
            node_id: "node-01",
            boot_id: [1; 16],
            sequence: 9,
            sent_mono_ms: 10_000,
            config_revision: 1,
        };
        let mut w = p::FrameWriter::new(&mut buf, &h, 512).unwrap();
        w.push(&p::Record::WifiLink(p::WifiLink {
            age_ms: 100,
            status: p::LinkStatus::Connected,
            rssi_dbm: Some(-60),
            channel: 1,
            bssid: Some([2, 0, 0, 0, 0, 1]),
            assoc_gen: 1,
        }))
        .unwrap();
        w.push(&p::Record::Probe(p::Probe {
            age_ms: 50,
            target_id: "gw-icmp",
            kind: p::ProbeKind::Icmp,
            outcome: p::ProbeOutcome::Timeout,
            rtt_us: None,
            scan_overlap: false,
            dscp: 0,
            sched_late_ms: 0,
            error_code: -1,
            dns: None,
        }))
        .unwrap();
        let n = w.finish();
        let f = p::decode_frame(&buf[..n]).unwrap();
        let mut clock = OffsetEstimator::default();
        clock.observe([1; 16], 10_000, 1_000_010_000);
        let obs = normalize(&f, &FrameCtx { received_at: 1_000_010_000, clock: &clock, current_bssid: None });
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[1].prov.index, 1);
        assert_eq!(obs[1].time.observed_at, 1_000_010_000 - 50);
        match &obs[1].kind {
            ObsKind::Probe(pr) => {
                assert_eq!(pr.rtt_us, None);
                assert_eq!(pr.outcome, Outcome::Timeout);
                assert_eq!(pr.via_bssid.as_deref(), Some("02:00:00:00:00:01"));
            }
            k => panic!("{k:?}"),
        }
    }
}
