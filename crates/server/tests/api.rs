//! In-process integration test: real router, writer thread, SQLite file, engine and
//! ingestion pipeline (MQTT transport replaced by direct calls to `ingest::handle`).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use ho_domain::SiteConfig;
use ho_logic::engine::Engine;
use ho_protocol as p;
use ho_server::{api, auth, ingest, writer, Metrics, Shared};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const OP: &str = "operator-token-aaaaaaaaaaaaaaaaaaaa";
const VIEW: &str = "viewer-token-bbbbbbbbbbbbbbbbbbbbbbbb";

fn cfg(db: &std::path::Path) -> SiteConfig {
    let mut c = ho_simulator::sim_config();
    c.server.database_path = db.to_string_lossy().into_owned();
    c.mqtt.enabled = false;
    c
}

async fn start() -> (String, Arc<Shared>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.sqlite");
    let c = cfg(&db);
    let store = ho_storage::Store::open(&db).unwrap();
    let w = writer::spawn(store, 256);
    let engine = Engine::new(c.clone());
    let snap = Arc::new(engine.snapshot());
    let app = Arc::new(Shared {
        cfg: c,
        config_path: None,
        db_path: db,
        engine: Mutex::new(engine),
        snapshot: RwLock::new(snap),
        writer: w,
        metrics: Metrics::default(),
        events: tokio::sync::broadcast::channel(64).0,
        tokens: auth::Tokens::parse(&format!("operator={OP}\nviewer={VIEW}\n")).unwrap(),
        mqtt: RwLock::new(None),
        mqtt_connected: AtomicBool::new(false),
        started_at: 0,
        desired_revision: AtomicU64::new(1),
        server_seq: AtomicU64::new(0),
        echo_stats: Arc::new(Mutex::new((0, 0))),
        ingest: Mutex::new(Default::default()),
        dashboard_dir: None,
        notifier_tokens: Default::default(),
        watchdog_ok: Mutex::new(None),
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let router = api::router(app.clone());
    tokio::spawn(async move { axum::serve(l, router).await });
    (base, app, dir)
}

fn frame(node: &str, kind: p::MsgKind, flags: u8, seq: u64) -> Vec<u8> {
    let h = p::Header {
        kind,
        flags,
        node_id: node,
        boot_id: [9; 16],
        sequence: seq,
        sent_mono_ms: 10_000 + seq * 2000,
        config_revision: 1,
    };
    let mut buf = [0u8; 512];
    let mut w = p::FrameWriter::new(&mut buf, &h, 512).unwrap();
    if kind == p::MsgKind::Events {
        w.push(&p::Record::Lifecycle(p::Lifecycle {
            age_ms: 5,
            event: p::LifecycleEvent::Boot,
            reason: 6,
            prior_bssid: None,
            new_bssid: None,
            duration_ms: None,
        }))
        .unwrap();
    } else {
        w.push(&p::Record::Probe(p::Probe {
            age_ms: 10,
            target_id: "gw-icmp",
            kind: p::ProbeKind::Icmp,
            outcome: p::ProbeOutcome::Success,
            rtt_us: Some(2500),
            scan_overlap: false,
            dscp: 0,
            sched_late_ms: 0,
            error_code: 0,
            dns: None,
        }))
        .unwrap();
    }
    let n = w.finish();
    buf[..n].to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_auth_ingest_and_safety() {
    let (base, app, _dir) = start().await;
    let c = reqwest::Client::new();
    // Health is public; everything else needs a token.
    assert_eq!(
        c.get(format!("{base}/health/live"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let r = c
        .get(format!("{base}/api/v1/site/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["code"], "unauthorized");
    assert!(body["request_id"].is_string());
    assert_eq!(
        c.get(format!("{base}/api/v1/site/status"))
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        c.get(format!("{base}/api/v1/site/status"))
            .bearer_auth(VIEW)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // Viewer cannot write.
    assert_eq!(
        c.post(format!("{base}/api/v1/notifications/test"))
            .bearer_auth(VIEW)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    // Ingestion: accept, dedup, reject spoof / unregistered / garbage / oversize.
    let pfx = "observatory/v1/home/nodes";
    let f1 = frame("node-01", p::MsgKind::Telemetry, 0, 1);
    ingest::handle(&app, &format!("{pfx}/node-01/telemetry"), &f1).await;
    ingest::handle(&app, &format!("{pfx}/node-01/telemetry"), &f1).await;
    ingest::handle(&app, &format!("{pfx}/node-02/telemetry"), &f1).await; // spoofed topic
    ingest::handle(&app, &format!("{pfx}/intruder/telemetry"), &f1).await;
    ingest::handle(&app, &format!("{pfx}/node-01/telemetry"), b"not a frame").await;
    ingest::handle(&app, &format!("{pfx}/node-01/telemetry"), &vec![0u8; 4000]).await;
    ingest::handle(&app, &format!("{pfx}/node-01/ack"), &f1).await; // nodes never publish acks
    let ev = frame("node-01", p::MsgKind::Events, p::flags::NEEDS_ACK, 2);
    ingest::handle(&app, &format!("{pfx}/node-01/events"), &ev).await;
    let m = &app.metrics;
    assert_eq!(m.frames_accepted.load(Ordering::Relaxed), 2);
    assert_eq!(m.frames_duplicate.load(Ordering::Relaxed), 1);
    let rej = m.rejected.lock().unwrap().clone();
    for k in [
        "envelope_topic_mismatch",
        "unregistered_node",
        "bad_magic",
        "too_large",
        "unexpected_suffix",
    ] {
        assert_eq!(rej.get(k), Some(&1), "{k}: {rej:?}");
    }
    let st: serde_json::Value = c
        .get(format!("{base}/api/v1/site/status"))
        .bearer_auth(VIEW)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        st["storage"]["batches"], 2,
        "duplicates never stored twice: {st}"
    );
    assert_eq!(st["storage"]["lifecycle_events"], 1);

    // Metrics queries are allowlisted and bounded.
    assert_eq!(
        c.get(format!("{base}/api/v1/metrics/query?target=http://evil"))
            .bearer_auth(VIEW)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let q = c
        .get(format!(
            "{base}/api/v1/metrics/query?target=gw-icmp&hours=1"
        ))
        .bearer_auth(VIEW)
        .send()
        .await
        .unwrap();
    assert_eq!(q.status(), 200);
    let q: serde_json::Value = q.json().await.unwrap();
    assert_eq!(q["series"][0]["points"][0]["eligible"], 1);
    // Diagnostics: only allowlisted jobs.
    let d = c
        .post(format!("{base}/api/v1/diagnostics/jobs"))
        .bearer_auth(OP)
        .json(&serde_json::json!({"job": "port-scan"}))
        .send()
        .await
        .unwrap();
    assert_eq!(d.status(), 400);
    let d = c
        .post(format!("{base}/api/v1/diagnostics/jobs"))
        .bearer_auth(OP)
        .json(&serde_json::json!({"job": "check-now", "check": "not-configured"}))
        .send()
        .await
        .unwrap();
    assert_eq!(d.status(), 400);

    // Security-sensitive config sections cannot be changed over HTTP.
    let mut evil = app.cfg.clone();
    evil.mqtt.password_file = Some("/etc/shadow".into());
    let y = serde_yaml_to_string(&evil);
    let r = c
        .put(format!("{base}/api/v1/admin/config"))
        .bearer_auth(OP)
        .json(&serde_json::json!({"yaml": y, "dry_run": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    let b: serde_json::Value = r.json().await.unwrap();
    assert_eq!(b["code"], "locked_section");
    let ok = c
        .put(format!("{base}/api/v1/admin/config"))
        .bearer_auth(OP)
        .json(&serde_json::json!({"yaml": serde_yaml_to_string(&app.cfg), "dry_run": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Devices never expose matcher material.
    let dv = c
        .get(format!("{base}/api/v1/devices"))
        .bearer_auth(VIEW)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!dv.contains("11111111-2222"), "matcher UUID leaked");
    // Notification test is labeled and queued, not claimed delivered.
    let t: serde_json::Value = c
        .post(format!("{base}/api/v1/notifications/test"))
        .bearer_auth(OP)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(t["queued"], 1);
    // Prometheus requires auth and exposes low-cardinality counters.
    assert_eq!(
        c.get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let pm = c
        .get(format!("{base}/metrics"))
        .bearer_auth(VIEW)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(pm.contains("ho_frames_total{result=\"accepted\"} 2"));
    assert!(!pm.contains("02:00:00"), "no MAC labels");
    // OpenAPI is served.
    let oa = c
        .get(format!("{base}/api/v1/openapi.json"))
        .bearer_auth(VIEW)
        .send()
        .await
        .unwrap();
    assert_eq!(oa.status(), 200);
}

fn serde_yaml_to_string(c: &SiteConfig) -> String {
    serde_json::to_string(c).unwrap() // JSON is valid YAML
}
