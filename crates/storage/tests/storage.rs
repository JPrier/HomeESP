#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ho_domain::*;
use ho_storage::*;

fn meta(seq: u64, at: UnixMs) -> BatchMeta {
    BatchMeta {
        site_id: "home".into(),
        node_id: "node-01".into(),
        boot_id: "b1".into(),
        sequence: seq,
        kind: 1,
        flags: 0,
        received_at: at,
        sent_mono_ms: 1000,
        config_revision: 0,
        record_count: 1,
        bytes: 100,
        clock_uncertainty_ms: Some(20),
    }
}

fn probe(at: UnixMs, idx: u16, seq: u64, outcome: Outcome, rtt: Option<u32>) -> Observation {
    Observation {
        prov: Provenance {
            source: "node-01".into(),
            boot_id: "b1".into(),
            sequence: seq,
            index: idx,
        },
        time: EventTime {
            observed_at: at,
            uncertainty_ms: 20,
            received_at: at,
        },
        kind: ObsKind::Probe(ProbeObs {
            target_id: "gw-icmp".into(),
            kind: "icmp".into(),
            outcome,
            rtt_us: rtt,
            scan_overlap: false,
            dscp: 0,
            sched_late_ms: 0,
            error_code: 0,
            dns: None,
            via_bssid: None,
        }),
    }
}

#[test]
fn migrates_and_reports_version() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.schema_version().unwrap(), 1);
    assert_eq!(s.integrity_check().unwrap(), "ok");
}

#[test]
fn duplicate_frames_are_idempotent() {
    let mut s = Store::open_in_memory().unwrap();
    let o = [probe(60_000, 0, 1, Outcome::Success, Some(1500))];
    assert!(matches!(
        s.insert_frame(&meta(1, 60_000), &o).unwrap(),
        InsertOutcome::Inserted(_)
    ));
    assert_eq!(
        s.insert_frame(&meta(1, 60_000), &o).unwrap(),
        InsertOutcome::Duplicate
    );
    let c = s.counts().unwrap();
    assert_eq!(c["batches"], 1);
    assert_eq!(c["probe_results"], 1);
}

#[test]
fn db_rejects_rtt_on_failed_probe() {
    let mut s = Store::open_in_memory().unwrap();
    let bad = [probe(60_000, 0, 1, Outcome::Timeout, Some(5))];
    assert!(
        s.insert_frame(&meta(1, 60_000), &bad).is_err(),
        "CHECK constraint must refuse RTT on failure"
    );
    assert_eq!(s.counts().unwrap()["batches"], 0, "transaction rolled back");
}

#[test]
fn rollups_and_series_preserve_loss_denominator() {
    let mut s = Store::open_in_memory().unwrap();
    let base = 1_700_000_000_000i64 - 1_700_000_000_000i64 % 60_000;
    for i in 0..20u64 {
        let ok = i % 4 != 0;
        let at = base + i as i64 * 5_000;
        let o = [probe(
            at,
            0,
            i + 1,
            if ok {
                Outcome::Success
            } else {
                Outcome::Timeout
            },
            ok.then_some(2000 + i as u32 * 10),
        )];
        s.insert_frame(&meta(i + 1, at), &o).unwrap();
    }
    let series = s
        .probe_series("gw-icmp", None, base, base + 120_000, 100)
        .unwrap();
    assert_eq!(series.len(), 1);
    let pts = &series[0].points;
    assert_eq!(pts.len(), 2);
    let total_eligible: i64 = pts.iter().map(|p| p.eligible).sum();
    assert_eq!(total_eligible, 20);
    assert!((pts[0].loss_pct.unwrap() - 25.0).abs() < 1e-9);
    assert!(pts[0].p95_ms.unwrap() > 1.9);
    // Hour compaction keeps totals exact.
    let n = s.rollup_hours(base + 3 * 3_600_000).unwrap();
    assert!(n >= 1);
    let again = s.rollup_hours(base + 3 * 3_600_000).unwrap();
    assert_eq!(again, 0, "idempotent");
}

#[test]
fn outbox_dedup_retry_and_permanent_failure() {
    let mut s = Store::open_in_memory().unwrap();
    let item = (
        "inc-1|opened|1|ntfy".to_string(),
        "ntfy".to_string(),
        "{}".to_string(),
        1000i64,
        false,
    );
    s.commit_derived(
        &[],
        &[],
        std::slice::from_ref(&item),
        &[],
        Some(("checkpoint", "1")),
    )
    .unwrap();
    s.commit_derived(&[], &[], &[item], &[], None).unwrap();
    let due = s.outbox_due(1000, 10).unwrap();
    assert_eq!(due.len(), 1, "dedup key prevents duplicates");
    s.outbox_attempt(due[0].id, 1000, false, Some("timeout"), Some(5000))
        .unwrap();
    assert!(s.outbox_due(2000, 10).unwrap().is_empty());
    let due = s.outbox_due(5000, 10).unwrap();
    assert_eq!(due[0].attempts, 1);
    s.outbox_attempt(due[0].id, 5000, false, Some("403"), None)
        .unwrap();
    assert_eq!(s.outbox_list(Some("failed"), 10).unwrap().len(), 1);
    assert_eq!(s.kv_get("checkpoint").unwrap().as_deref(), Some("1"));
}

#[test]
fn suppressed_notifications_are_recorded_not_due() {
    let mut s = Store::open_in_memory().unwrap();
    s.commit_derived(
        &[],
        &[],
        &[("k".into(), "ntfy".into(), "{}".into(), 0, true)],
        &[],
        None,
    )
    .unwrap();
    assert!(s.outbox_due(10, 10).unwrap().is_empty());
    assert_eq!(s.outbox_list(Some("suppressed"), 10).unwrap().len(), 1);
}

#[test]
fn retention_is_bounded_and_cascades() {
    let mut s = Store::open_in_memory().unwrap();
    for i in 0..50u64 {
        s.insert_frame(
            &meta(i + 1, i as i64),
            &[probe(i as i64, 0, i + 1, Outcome::Success, Some(100))],
        )
        .unwrap();
    }
    let now = 30 * 86_400_000i64;
    let r = Retention::default();
    let rep = s.retention(now, &r, 20).unwrap();
    assert_eq!(rep.raw_batches, 20, "bounded batch");
    s.retention(now, &r, 100).unwrap();
    let c = s.counts().unwrap();
    assert_eq!(c["batches"], 0);
    assert_eq!(
        c["probe_results"], 0,
        "observations cascade with their batch"
    );
}

#[test]
fn backup_and_restore_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.sqlite");
    let bak = dir.path().join("backup.sqlite");
    let mut s = Store::open(&db).unwrap();
    s.insert_frame(
        &meta(1, 10),
        &[probe(10, 0, 1, Outcome::Success, Some(100))],
    )
    .unwrap();
    s.backup_to(&bak).unwrap();
    s.insert_frame(
        &meta(2, 20),
        &[probe(20, 0, 2, Outcome::Success, Some(100))],
    )
    .unwrap();
    let restored = Store::open(&bak).unwrap();
    assert_eq!(restored.integrity_check().unwrap(), "ok");
    assert_eq!(restored.counts().unwrap()["batches"], 1);
}

#[test]
fn purge_device_removes_identity_data() {
    let mut s = Store::open_in_memory().unwrap();
    let ble = Observation {
        prov: Provenance {
            source: "node-01".into(),
            boot_id: "b1".into(),
            sequence: 1,
            index: 0,
        },
        time: EventTime {
            observed_at: 1,
            uncertainty_ms: 20,
            received_at: 1,
        },
        kind: ObsKind::Ble(BleObs {
            device_id: "phone-1".into(),
            window_ms: 2000,
            count: 3,
            rssi_min: -70,
            rssi_max: -60,
            rssi_mean: -65.0,
            last_seen_age_ms: 10,
            coverage_permille: 900,
        }),
    };
    s.insert_frame(&meta(1, 1), &[ble]).unwrap();
    assert!(s.purge_device("phone-1").unwrap() >= 1);
    assert_eq!(s.counts().unwrap()["ble_windows"], 0);
}

#[test]
fn rejects_future_schema() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("x.sqlite");
    {
        let s = Store::open(&db).unwrap();
        s.conn().pragma_update(None, "user_version", 99).unwrap();
    }
    assert!(matches!(Store::open(&db), Err(StoreError::TooNew { .. })));
}
