//! Malformed-input, bounds and property tests for the decoder/encoder.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ho_protocol::*;
use proptest::prelude::*;

fn hdr(node_id: &str) -> Header<'_> {
    Header {
        kind: MsgKind::Telemetry,
        flags: 0,
        node_id,
        boot_id: [7; 16],
        sequence: 1,
        sent_mono_ms: 10,
        config_revision: 0,
    }
}

fn probe(target: &str, outcome: ProbeOutcome, rtt: Option<u32>) -> Record<'_> {
    Record::Probe(Probe {
        age_ms: 1,
        target_id: target,
        kind: ProbeKind::Icmp,
        outcome,
        rtt_us: rtt,
        scan_overlap: false,
        dscp: 0,
        sched_late_ms: 0,
        error_code: 0,
        dns: None,
    })
}

fn one_probe_frame() -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut w = FrameWriter::new(&mut buf, &hdr("node-01"), 256).unwrap();
    w.push(&probe("gw", ProbeOutcome::Success, Some(900)))
        .unwrap();
    let n = w.finish();
    buf[..n].to_vec()
}

#[test]
fn rejects_bad_magic_schema_kind() {
    let mut f = one_probe_frame();
    f[0] = b'X';
    assert_eq!(decode_frame(&f).unwrap_err(), DecodeError::BadMagic);
    let mut f = one_probe_frame();
    f[2] = 2;
    assert_eq!(
        decode_frame(&f).unwrap_err(),
        DecodeError::UnsupportedSchema(2)
    );
    let mut f = one_probe_frame();
    f[4] = 99;
    assert_eq!(decode_frame(&f).unwrap_err(), DecodeError::UnknownKind(99));
}

#[test]
fn rejects_oversized_and_trailing() {
    let big = vec![0u8; MAX_FRAME_BYTES + 1];
    assert_eq!(decode_frame(&big).unwrap_err(), DecodeError::TooLarge);
    let mut f = one_probe_frame();
    f.push(0);
    assert_eq!(decode_frame(&f).unwrap_err(), DecodeError::TrailingBytes);
}

#[test]
fn every_truncation_is_rejected_without_panic() {
    let f = one_probe_frame();
    for n in 0..f.len() {
        assert!(decode_frame(&f[..n]).is_err(), "prefix {n} accepted");
    }
}

#[test]
fn bad_node_ids_rejected() {
    for id in ["", "Node", "-a", "a-", "a b", "x".repeat(33).as_str()] {
        let mut buf = [0u8; 128];
        assert!(FrameWriter::new(&mut buf, &hdr(id), 128).is_err(), "{id:?}");
    }
    assert!(valid_node_id("node-01"));
}

#[test]
fn rtt_only_on_success() {
    let mut buf = [0u8; 128];
    let mut w = FrameWriter::new(&mut buf, &hdr("n1"), 128).unwrap();
    assert_eq!(
        w.push(&probe("gw", ProbeOutcome::Timeout, Some(5)))
            .unwrap_err(),
        EncodeError::InvalidField
    );
    assert_eq!(
        w.push(&probe("gw", ProbeOutcome::Success, None))
            .unwrap_err(),
        EncodeError::InvalidField
    );
    // Hand-craft a frame whose timeout claims an RTT: decoder must refuse it.
    let mut f = one_probe_frame();
    // outcome byte sits after: header(...) count(1) type(1) len(2) age(4) idlen(1) id(2) kind(1)
    let hdr_len = HEADER_FIXED_BYTES + "node-01".len();
    let outcome_at = hdr_len + 1 + 2 + 4 + 1 + 2 + 1;
    f[outcome_at] = ProbeOutcome::Timeout as u8;
    assert!(matches!(
        decode_frame(&f),
        Err(DecodeError::InvalidField { .. })
    ));
}

#[test]
fn unknown_record_types_are_skipped_and_long_records_keep_prefix() {
    let mut f = one_probe_frame();
    // Append an unknown record type 200 with 3 payload bytes, bump the count.
    let hdr_len = HEADER_FIXED_BYTES + "node-01".len();
    f[hdr_len - 1] += 1;
    f.extend_from_slice(&[200, 3, 0, 1, 2, 3]);
    let frame = decode_frame(&f).unwrap();
    let recs: Vec<_> = frame.records().collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[1], Record::Unknown { rtype: 200, len: 3 });

    // A NodeStatus with 4 extra trailing bytes (future additive fields) still decodes.
    let mut buf = [0u8; 128];
    let mut w = FrameWriter::new(&mut buf, &hdr("n1"), 128).unwrap();
    w.push(&Record::NodeStatus(NodeStatus {
        online: true,
        reason: 0,
        uptime_s: 5,
    }))
    .unwrap();
    let n = w.finish();
    let mut v = buf[..n].to_vec();
    let len_at = HEADER_FIXED_BYTES + 2 + 1;
    v[len_at] += 4;
    v.extend_from_slice(&[9, 9, 9, 9]);
    let fr = decode_frame(&v).unwrap();
    assert!(matches!(fr.records().next(), Some(Record::NodeStatus(s)) if s.uptime_s == 5));
}

#[test]
fn writer_is_unchanged_after_failed_push() {
    let mut buf = [0u8; 80];
    let mut w = FrameWriter::new(&mut buf, &hdr("node-01"), 80).unwrap();
    w.push(&probe("gw", ProbeOutcome::Success, Some(1)))
        .unwrap();
    let before = w.len();
    let err = w.push(&probe(
        "a-much-longer-target-id",
        ProbeOutcome::Success,
        Some(1),
    ));
    assert_eq!(err.unwrap_err(), EncodeError::BufferFull);
    assert_eq!(w.len(), before);
    let n = w.finish();
    let f = decode_frame(&buf[..n]).unwrap();
    assert_eq!(f.record_count, 1);
}

#[test]
fn max_frame_limit_is_enforced() {
    let mut buf = [0u8; 4096];
    let mut w = FrameWriter::new(&mut buf, &hdr("node-01"), 4096).unwrap();
    let mut pushed = 0;
    while w
        .push(&probe("gateway-icmp", ProbeOutcome::Success, Some(1)))
        .is_ok()
    {
        pushed += 1;
    }
    let n = w.finish();
    assert!(n <= MAX_FRAME_BYTES);
    assert!(pushed > 10);
    assert!(decode_frame(&buf[..n]).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, .. ProptestConfig::default() })]

    #[test]
    fn decoder_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..1200)) {
        let _ = decode_frame(&bytes);
    }

    #[test]
    fn decoder_total_on_mutated_valid_frames(idx in 0usize..64, val in any::<u8>()) {
        let mut f = one_probe_frame();
        let i = idx % f.len();
        f[i] = val;
        if let Ok(fr) = decode_frame(&f) {
            // Iteration over a validated frame must yield exactly record_count items.
            prop_assert_eq!(fr.records().count(), fr.record_count as usize);
        }
    }

    #[test]
    fn probe_roundtrip(age in any::<u32>(), rtt in any::<u32>(), late in any::<u16>(),
                       err in any::<i16>(), dscp in 0u8..64, ok in any::<bool>(),
                       seq in any::<u64>(), mono in any::<u64>()) {
        let outcome = if ok { ProbeOutcome::Success } else { ProbeOutcome::Timeout };
        let rec = Record::Probe(Probe {
            age_ms: age, target_id: "t1", kind: ProbeKind::UdpEcho, outcome,
            rtt_us: ok.then_some(rtt), scan_overlap: !ok, dscp, sched_late_ms: late,
            error_code: err, dns: None,
        });
        let h = Header { sequence: seq, sent_mono_ms: mono, ..hdr("n-1") };
        let mut buf = [0u8; 256];
        let mut w = FrameWriter::new(&mut buf, &h, 256).unwrap();
        w.push(&rec).unwrap();
        let n = w.finish();
        let f = decode_frame(&buf[..n]).unwrap();
        prop_assert_eq!(f.header, h);
        prop_assert_eq!(f.records().next(), Some(rec));
    }

    #[test]
    fn wifi_roundtrip(rssi in proptest::option::of(any::<i8>()), ch in 0u8..15,
                      bssid in proptest::option::of(any::<[u8; 6]>()), generation in any::<u16>()) {
        let rec = Record::WifiLink(WifiLink {
            age_ms: 5, status: LinkStatus::Connected, rssi_dbm: rssi, channel: ch,
            bssid, assoc_gen: generation,
        });
        let mut buf = [0u8; 128];
        let mut w = FrameWriter::new(&mut buf, &hdr("n"), 128).unwrap();
        w.push(&rec).unwrap();
        let n = w.finish();
        let f = decode_frame(&buf[..n]).unwrap();
        prop_assert_eq!(f.records().next(), Some(rec));
    }
}
