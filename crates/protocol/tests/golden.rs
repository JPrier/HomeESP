//! Golden vectors shared with the C++ firmware codec (`firmware/test/test_codec.cpp`).
//! Regenerate deliberately with `UPDATE_GOLDEN=1 cargo test -p ho-protocol --test golden`;
//! a diff in these files is a wire-format change and needs a schema review.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ho_protocol::*;
use std::path::PathBuf;

const BOOT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

fn header(kind: MsgKind, flags: u8, seq: u64) -> Header<'static> {
    Header {
        kind,
        flags,
        node_id: "node-01",
        boot_id: BOOT,
        sequence: seq,
        sent_mono_ms: 123_456,
        config_revision: 7,
    }
}

fn build(h: Header<'_>, recs: &[Record<'_>]) -> Vec<u8> {
    let mut buf = [0u8; MAX_FRAME_BYTES];
    let mut w = FrameWriter::new(&mut buf, &h, MAX_FRAME_BYTES).unwrap();
    for r in recs {
        w.push(r).unwrap();
    }
    let n = w.finish();
    buf[..n].to_vec()
}

pub fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    let ap = [
        ApEntry {
            bssid: MAC_A,
            channel: 1,
            rssi_dbm: -58,
        },
        ApEntry {
            bssid: MAC_B,
            channel: 6,
            rssi_dbm: -77,
        },
    ];
    let mut counts = [0u8; 14];
    counts[0] = 9;
    counts[5] = 4;
    counts[10] = 7;
    vec![
        (
            "telemetry_basic",
            build(
                header(MsgKind::Telemetry, 0, 42),
                &[
                    Record::WifiLink(WifiLink {
                        age_ms: 100,
                        status: LinkStatus::Connected,
                        rssi_dbm: Some(-61),
                        channel: 6,
                        bssid: Some(MAC_A),
                        assoc_gen: 3,
                    }),
                    Record::Probe(Probe {
                        age_ms: 50,
                        target_id: "gw-icmp",
                        kind: ProbeKind::Icmp,
                        outcome: ProbeOutcome::Success,
                        rtt_us: Some(2345),
                        scan_overlap: false,
                        dscp: 0,
                        sched_late_ms: 3,
                        error_code: 0,
                        dns: None,
                    }),
                    Record::Probe(Probe {
                        age_ms: 40,
                        target_id: "dns-local",
                        kind: ProbeKind::Dns,
                        outcome: ProbeOutcome::Timeout,
                        rtt_us: None,
                        scan_overlap: true,
                        dscp: 0,
                        sched_late_ms: 0,
                        error_code: -1,
                        dns: Some(DnsDetail {
                            rcode: 0,
                            answer: DnsAnswer::NoAnswer,
                            transport: 0,
                            qtype: 1,
                        }),
                    }),
                    Record::System(System {
                        age_ms: 0,
                        uptime_s: 3600,
                        heap_free: 41_000,
                        heap_min: 38_500,
                        heap_max_block: 30_000,
                        heap_frag_pct: 12,
                        reset_reason: 6,
                        queue_fill_pct: 25,
                        drops_overflow: 1,
                        drops_budget: 2,
                        drops_expired: 3,
                        missed_schedules: 4,
                        loop_lag_max_ms: 15,
                        reconnects: 2,
                        tx_bytes: 100_000,
                        tx_frames: 500,
                        fw_version: "0.1.0",
                    }),
                ],
            ),
        ),
        (
            "events_lifecycle",
            build(
                header(MsgKind::Events, flags::NEEDS_ACK, 43),
                &[
                    Record::Lifecycle(Lifecycle {
                        age_ms: 5000,
                        event: LifecycleEvent::WifiDisconnected,
                        reason: 201,
                        prior_bssid: Some(MAC_A),
                        new_bssid: None,
                        duration_ms: Some(5000),
                    }),
                    Record::Lifecycle(Lifecycle {
                        age_ms: 9000,
                        event: LifecycleEvent::Boot,
                        reason: 6,
                        prior_bssid: None,
                        new_bssid: None,
                        duration_ms: None,
                    }),
                ],
            ),
        ),
        (
            "ap_scan",
            build(
                header(MsgKind::Telemetry, 0, 44),
                &[Record::ApScan(ApScan {
                    age_ms: 10,
                    scan_id: 5,
                    duration_ms: 1800,
                    completeness: ScanCompleteness::Complete,
                    channel_counts: counts,
                    entries: ApEntries::List(&ap),
                })],
            ),
        ),
        (
            "capabilities",
            build(
                header(MsgKind::Capabilities, 0, 1),
                &[
                    Record::Capabilities(Capabilities {
                        chip: "ESP8266EX",
                        flash_kb: 4096,
                        ram_kb: 80,
                        features: feature::WIFI_STA
                            | feature::AP_SCAN_PASSIVE
                            | feature::PROBE_ICMP
                            | feature::PROBE_UDP_ECHO
                            | feature::PROBE_DNS
                            | feature::PROBE_TCP,
                        fw_version: "0.1.0",
                        profile: "esp8266-4m",
                        max_payload: 1024,
                        max_probe_targets: 8,
                        max_tracked_bssids: 16,
                        max_ble_devices: 0,
                    }),
                    Record::NodeStatus(NodeStatus {
                        online: true,
                        reason: 0,
                        uptime_s: 12,
                    }),
                ],
            ),
        ),
        (
            "config_desired",
            build(
                Header {
                    boot_id: [0; 16],
                    ..header(MsgKind::ConfigDesired, 0, 9)
                },
                &[
                    Record::ConfigParams(ConfigParams {
                        revision: 7,
                        report_ms: 2000,
                        wifi_link_ms: 5000,
                        ap_scan_ms: 120_000,
                        heartbeat_ms: 10_000,
                        health_ms: 60_000,
                        egress_bytes_per_sec: 600,
                        egress_burst_bytes: 1800,
                        max_payload: 1024,
                        offline_buffer_bytes: 8192,
                        flags: cfgflag::PASSIVE_SCAN,
                        max_probe_inflight: 2,
                        scan_max_dwell_ms: 120,
                    }),
                    Record::ProbeTarget(ProbeTarget {
                        id: "gw-icmp",
                        kind: ProbeKind::Icmp,
                        addr_source: AddrSource::Gateway,
                        ipv4: [0; 4],
                        port: 0,
                        interval_ms: 5000,
                        timeout_ms: 1000,
                        dscp: 0,
                        expect: DnsExpect::AnyAnswer,
                        expect_ipv4: [0; 4],
                        qtype: 0,
                        qname: "",
                    }),
                    Record::ProbeTarget(ProbeTarget {
                        id: "dns-local",
                        kind: ProbeKind::Dns,
                        addr_source: AddrSource::AssignedResolver,
                        ipv4: [0; 4],
                        port: 53,
                        interval_ms: 30_000,
                        timeout_ms: 2000,
                        dscp: 0,
                        expect: DnsExpect::Ipv4,
                        expect_ipv4: [192, 0, 2, 10],
                        qtype: 1,
                        qname: "router.home.arpa",
                    }),
                    Record::TrackedBssid(MAC_B),
                ],
            ),
        ),
        (
            "ack",
            build(
                Header {
                    boot_id: [0; 16],
                    ..header(MsgKind::Ack, 0, 10)
                },
                &[Record::Ack(Ack {
                    boot_id: BOOT,
                    sequence: 43,
                })],
            ),
        ),
        (
            "ble_sensor",
            build(
                header(MsgKind::Telemetry, 0, 45),
                &[
                    Record::Ble(BleSummary {
                        age_ms: 0,
                        window_ms: 2000,
                        device_id: "tag-01",
                        count: 4,
                        rssi_min: -80,
                        rssi_max: -70,
                        rssi_sum: -300,
                        last_seen_age_ms: 150,
                        coverage_permille: 900,
                    }),
                    Record::Sensor(Sensor {
                        age_ms: 20,
                        sensor_id: "temp-1",
                        kind: 1,
                        unit: 1,
                        value_milli: 21_500,
                        quality: 100,
                        calibration_rev: 2,
                    }),
                ],
            ),
        ),
    ]
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/protocol")
}

#[test]
fn golden_vectors_match_files() {
    let dir = golden_dir();
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    if update {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, bytes) in vectors() {
        let path = dir.join(format!("{name}.hex"));
        let hex = hex::encode(&bytes);
        if update {
            std::fs::write(&path, format!("{hex}\n")).unwrap();
            continue;
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing golden {path:?}; run with UPDATE_GOLDEN=1"));
        assert_eq!(want.trim(), hex, "golden mismatch for {name}");
    }
}

#[test]
fn golden_vectors_decode_and_roundtrip() {
    for (name, bytes) in vectors() {
        let f = decode_frame(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(f.header.node_id, "node-01");
        let recs: Vec<_> = f.records().collect();
        assert_eq!(recs.len(), f.record_count as usize, "{name}");
        // Re-encode decoded records: must be byte-identical.
        let again = build(f.header, &recs);
        assert_eq!(again, bytes, "{name} re-encode differs");
    }
}

#[test]
fn telemetry_fields_decode_exactly() {
    let v = vectors();
    let f = decode_frame(&v[0].1).unwrap();
    assert_eq!(f.header.sequence, 42);
    assert_eq!(f.header.kind, MsgKind::Telemetry);
    let recs: Vec<_> = f.records().collect();
    match recs[1] {
        Record::Probe(p) => {
            assert_eq!(p.target_id, "gw-icmp");
            assert_eq!(p.rtt_us, Some(2345));
        }
        other => panic!("unexpected {other:?}"),
    }
    match recs[2] {
        Record::Probe(p) => {
            assert_eq!(p.outcome, ProbeOutcome::Timeout);
            assert_eq!(p.rtt_us, None, "failed probes never carry an RTT");
            assert!(p.scan_overlap);
            assert_eq!(p.dns.unwrap().answer, DnsAnswer::NoAnswer);
        }
        other => panic!("unexpected {other:?}"),
    }
}
