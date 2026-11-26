//! Long-running tasks: MQTT session, ingest worker, engine ticks, outbox delivery,
//! central checks, UDP echo, Home Assistant publishing, maintenance and watchdog.

use crate::{effects, ingest, now_ms, writer::WriteCmd, App, Metrics};
use ho_collectors::echo::{self, EchoResponder};
use ho_integrations::{ha, notify};
use ho_logic::engine::Input;
use rumqttc::{AsyncClient, Event, EventLoop, LastWill, MqttOptions, Packet, QoS, Transport};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Build the MQTT client and event loop from config.
pub fn mqtt_client(app_cfg: &ho_domain::SiteConfig, password: Option<String>) -> Result<(AsyncClient, EventLoop), String> {
    let m = &app_cfg.mqtt;
    let mut o = MqttOptions::new(format!("observatory-server-{}", app_cfg.site_id), &m.host, m.port);
    o.set_keep_alive(Duration::from_secs(u64::from(m.keepalive_s.max(5))));
    o.set_max_packet_size(8192, 8192);
    o.set_clean_session(false);
    if let Some(p) = password {
        o.set_credentials(&m.username, p);
    }
    if let Some(ca) = &m.tls_ca_file {
        let ca = std::fs::read(ca).map_err(|e| format!("tls_ca_file: {e}"))?;
        o.set_transport(Transport::tls(ca, None, None));
    }
    if app_cfg.home_assistant.enabled {
        let w = ha::site_availability(app_cfg, false);
        o.set_last_will(LastWill::new(w.topic, w.payload, QoS::AtLeastOnce, true));
    }
    Ok(AsyncClient::new(o, 256))
}

/// Drive the MQTT session. Publishes are forwarded to the ingest worker through a
/// bounded queue so keepalives continue even when processing is slow.
pub async fn run_mqtt(app: App, client: AsyncClient, mut el: EventLoop, cancel: CancellationToken) {
    let (tx, rx) = mpsc::channel::<(String, Vec<u8>)>(app.cfg.server.ingest_queue.max(64));
    tokio::spawn(ingest_worker(app.clone(), rx));
    let prefix = app.cfg.topic_prefix();
    let mut backoff = Duration::from_secs(1);
    loop {
        let ev = tokio::select! {
            _ = cancel.cancelled() => break,
            ev = el.poll() => ev,
        };
        match ev {
            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                backoff = Duration::from_secs(1);
                app.mqtt_connected.store(true, Ordering::Relaxed);
                tracing::info!("mqtt connected");
                for (suffix, qos) in [
                    ("telemetry", QoS::AtMostOnce),
                    ("events", QoS::AtLeastOnce),
                    ("status", QoS::AtLeastOnce),
                    ("capabilities", QoS::AtLeastOnce),
                    ("config/reported", QoS::AtLeastOnce),
                ] {
                    if let Err(e) = client.subscribe(format!("{prefix}/nodes/+/{suffix}"), qos).await {
                        tracing::warn!(error = %e, "subscribe failed");
                    }
                }
                if app.cfg.home_assistant.enabled {
                    let _ = client.subscribe(format!("{}/status", app.cfg.home_assistant.discovery_prefix), QoS::AtLeastOnce).await;
                    publish_ha_discovery(&app, &client).await;
                }
                let fx = app.apply(Input::Ingestion { ok: true, at: now_ms() });
                effects::handle(&app, fx).await;
                let app2 = app.clone();
                tokio::spawn(async move { publish_all_desired(&app2).await });
            }
            Ok(Event::Incoming(Packet::Publish(p))) => {
                if app.cfg.home_assistant.enabled && p.topic == format!("{}/status", app.cfg.home_assistant.discovery_prefix) {
                    if p.payload.as_ref() == b"online" {
                        publish_ha_discovery(&app, &client).await; // HA restarted: republish
                    }
                    continue;
                }
                let is_telemetry = p.topic.ends_with("/telemetry");
                let item = (p.topic.clone(), p.payload.to_vec());
                if is_telemetry {
                    if tx.try_send(item).is_err() {
                        Metrics::inc(&app.metrics.frames_shed); // overload: shed disposable telemetry first
                        app.metrics.reject("ingest_queue_full");
                    }
                } else if tx.send(item).await.is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(e) => {
                if app.mqtt_connected.swap(false, Ordering::Relaxed) {
                    tracing::warn!(error = %e, "mqtt connection lost");
                    let fx = app.apply(Input::Ingestion { ok: false, at: now_ms() });
                    effects::handle(&app, fx).await;
                } else {
                    tracing::debug!(error = %e, "mqtt reconnect failed");
                }
                let jitter = Duration::from_millis(u64::from(rand::random::<u16>() % 1000));
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(backoff + jitter) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
    if app.cfg.home_assistant.enabled {
        let w = ha::site_availability(&app.cfg, false);
        let _ = client.publish(w.topic, QoS::AtLeastOnce, true, w.payload).await;
    }
    let _ = client.disconnect().await;
}

async fn ingest_worker(app: App, mut rx: mpsc::Receiver<(String, Vec<u8>)>) {
    while let Some((topic, payload)) = rx.recv().await {
        ingest::handle(&app, &topic, &payload).await;
    }
}

/// Publish (retained) desired config for one node.
pub async fn publish_desired(app: &App, node: &str) {
    let Some(client) = app.mqtt_client() else { return };
    let Some(nc) = app.cfg.node(node) else { return };
    let rev = app.desired_revision.load(Ordering::Relaxed);
    match crate::desired::desired_frame(&app.cfg, nc, rev, app.next_server_seq()) {
        Ok(f) => {
            let topic = format!("{}/nodes/{node}/config/desired", app.cfg.topic_prefix());
            if client.publish(topic, QoS::AtLeastOnce, true, f).await.is_ok() {
                let _ = app.writer.send(WriteCmd::Desired { node: node.into(), revision: rev }).await;
            }
        }
        Err(e) => tracing::error!(node, error = %e, "cannot encode desired config"),
    }
}

pub async fn publish_all_desired(app: &App) {
    for n in &app.cfg.nodes {
        publish_desired(app, n.id.as_str()).await;
    }
}

async fn publish_ha_discovery(app: &App, client: &AsyncClient) {
    for p in ha::discovery(&app.cfg) {
        let _ = client.publish(p.topic, QoS::AtLeastOnce, p.retain, p.payload).await;
    }
    let a = ha::site_availability(&app.cfg, true);
    let _ = client.publish(a.topic, QoS::AtLeastOnce, true, a.payload).await;
}

/// Publish HA states periodically, only when changed (avoid recorder flooding).
pub async fn run_ha(app: App, cancel: CancellationToken) {
    if !app.cfg.home_assistant.enabled {
        return;
    }
    let mut last: HashMap<String, String> = HashMap::new();
    let period = Duration::from_millis(u64::try_from(app.cfg.home_assistant.metrics_interval_ms.max(5000)).unwrap_or(30_000));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(period) => {}
        }
        let Some(client) = app.mqtt_client() else { continue };
        if !app.mqtt_connected.load(Ordering::Relaxed) {
            continue;
        }
        let snap = app.snapshot();
        let score = ho_logic::recommend::score(&snap, app.cfg.thresholds.loss_min_samples);
        for p in ha::states(&app.cfg, &snap, &score) {
            if last.get(&p.topic) == Some(&p.payload) {
                continue;
            }
            if client.publish(p.topic.clone(), QoS::AtLeastOnce, p.retain, p.payload.clone()).await.is_ok() {
                last.insert(p.topic, p.payload);
            }
        }
    }
}

/// Engine ticks (1 s): liveness, staleness, correlation, location windows.
pub async fn run_ticks(app: App, cancel: CancellationToken) {
    let mut iv = tokio::time::interval(Duration::from_secs(1));
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = iv.tick() => {}
        }
        let (fx, snap) = app.with_engine(|e| {
            let fx = e.apply(Input::Tick(now_ms()));
            (fx, e.snapshot())
        });
        if let Ok(mut s) = app.snapshot.write() {
            *s = std::sync::Arc::new(snap);
        }
        effects::handle(&app, fx).await;
    }
}

/// Deliver due outbox items with capped exponential backoff.
pub async fn run_outbox(app: App, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
        let now = now_ms();
        let due = match app.reader().and_then(|r| r.outbox_due(now, 20).map_err(|e| e.to_string())) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(error = %e, "outbox read failed");
                continue;
            }
        };
        for item in due {
            let Some(n) = app.cfg.notifications.notifiers.iter().find(|n| n.id == item.notifier) else {
                let _ = app
                    .writer
                    .send(WriteCmd::OutboxAttempt { id: item.id, now, ok: false, error: Some("unknown notifier".into()), retry_at: None })
                    .await;
                continue;
            };
            let Ok(msg) = serde_json::from_str::<notify::Message>(&item.payload) else { continue };
            let token = app.notifier_tokens.get(&n.id).map(String::as_str);
            let res = notify::deliver(n, token, &msg).await;
            let (ok, err, retry) = match res {
                Ok(()) => {
                    Metrics::inc(&app.metrics.notifications_sent);
                    (true, None, None)
                }
                Err(notify::DeliveryError::Transient(e)) if item.attempts + 1 < notify::MAX_ATTEMPTS => {
                    (false, Some(e), Some(now + notify::backoff_ms(item.attempts)))
                }
                Err(notify::DeliveryError::Transient(e)) | Err(notify::DeliveryError::Permanent(e)) => {
                    Metrics::inc(&app.metrics.notifications_failed);
                    (false, Some(e), None)
                }
            };
            let _ = app.writer.send(WriteCmd::OutboxAttempt { id: item.id, now, ok, error: err, retry_at: retry }).await;
        }
    }
}

/// Run configured central checks on deterministic staggered schedules.
pub async fn run_central(app: App, cancel: CancellationToken) {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    let boot = format!("{:032x}", rand::random::<u128>());
    let seq = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut handles = Vec::new();
    for check in app.cfg.central_checks.clone() {
        let (app, sem, cancel, boot, seq) = (app.clone(), sem.clone(), cancel.clone(), boot.clone(), seq.clone());
        handles.push(tokio::spawn(async move {
            let phase = crc(check.id.as_str()) % u64::from(check.interval_ms.max(1));
            tokio::select! { _ = cancel.cancelled() => return, _ = tokio::time::sleep(Duration::from_millis(phase)) => {} }
            let mut iv = tokio::time::interval(Duration::from_millis(u64::from(check.interval_ms)));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip); // never catch-up bursts
            loop {
                tokio::select! { _ = cancel.cancelled() => return, _ = iv.tick() => {} }
                let Ok(_permit) = sem.acquire().await else { return };
                let started = now_ms();
                let p = ho_collectors::run_check(&check).await;
                let s = seq.fetch_add(1, Ordering::Relaxed) + 1;
                record_central(&app, &boot, s, started, p).await;
            }
        }));
    }
    cancel.cancelled().await;
    for h in handles {
        h.abort();
    }
}

fn crc(s: &str) -> u64 {
    s.bytes().fold(1469598103934665603u64, |h, b| (h ^ u64::from(b)).wrapping_mul(1099511628211))
}

/// Persist and process one central observation.
pub async fn record_central(app: &App, boot: &str, seq: u64, at: i64, p: ho_domain::ProbeObs) {
    let obs = ho_domain::Observation {
        prov: ho_domain::Provenance { source: "central".into(), boot_id: boot.into(), sequence: seq, index: 0 },
        time: ho_domain::EventTime { observed_at: at, uncertainty_ms: 1, received_at: now_ms() },
        kind: ho_domain::ObsKind::Probe(p),
    };
    let meta = ho_storage::BatchMeta {
        site_id: app.cfg.site_id.to_string(),
        node_id: "central".into(),
        boot_id: boot.into(),
        sequence: seq,
        kind: 1,
        flags: 0,
        received_at: obs.time.received_at,
        sent_mono_ms: 0,
        config_revision: 0,
        record_count: 1,
        bytes: 0,
        clock_uncertainty_ms: Some(1),
    };
    if app.writer.insert_frame(meta, vec![obs.clone()]).await.is_err() {
        return;
    }
    let fx = app.apply(Input::Observations(vec![obs]));
    effects::handle(app, fx).await;
}

/// UDP echo responder.
pub async fn run_echo(app: App, keys: HashMap<String, Vec<u8>>, cancel: CancellationToken) {
    let Some(bind) = app.cfg.server.echo_bind.clone() else { return };
    let sock = match tokio::net::UdpSocket::bind(&bind).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, bind, "udp echo bind failed");
            return;
        }
    };
    tracing::info!(bind, nodes = keys.len(), "udp echo responder listening");
    let r = EchoResponder::new(keys, 2.0, 10.0);
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = echo::serve(sock, r, app.echo_stats.clone()) => {}
    }
}

/// Rollups, retention and storage budget.
pub async fn run_maintenance(app: App, cancel: CancellationToken) {
    let mut n: u64 = 0;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(600)) => {}
        }
        n += 1;
        let now = now_ms();
        let _ = app.writer.send(WriteCmd::RollupHours { now }).await;
        if n % 6 == 1 {
            let r = app.writer.call(|reply| WriteCmd::Retention { now, r: app.cfg.retention.clone(), reply }).await;
            tracing::info!(?r, "retention pass");
        }
        if let Ok(size) = app.reader().and_then(|s| s.size_bytes().map_err(|e| e.to_string())) {
            let limit = app.cfg.retention.max_db_mb.saturating_mul(1024 * 1024);
            if u64::try_from(size).unwrap_or(0) > limit / 10 * 9 {
                tracing::warn!(size, limit, "database above 90% of budget; retention will trim oldest raw data");
                let _ = app.writer.call(|reply| WriteCmd::Retention { now, r: ho_domain::Retention { raw_days: 1, ..app.cfg.retention.clone() }, reply }).await;
            }
        }
    }
}

/// External watchdog heartbeat (optional).
pub async fn run_watchdog(app: App, cancel: CancellationToken) {
    let Some(w) = app.cfg.watchdog.clone() else { return };
    loop {
        let ok = ho_integrations::watchdog::ping(&w.url, Duration::from_secs(10)).await;
        if let Ok(mut s) = app.watchdog_ok.lock() {
            *s = Some((now_ms(), ok.is_ok()));
        }
        if let Err(e) = ok {
            tracing::warn!(error = e, "watchdog heartbeat failed");
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_millis(w.interval_ms)) => {}
        }
    }
}
