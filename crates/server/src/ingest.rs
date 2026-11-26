//! MQTT intake: authenticate by topic, bound sizes before decoding, rate-limit per
//! node, check envelope identity, deduplicate, persist durably, ACK critical events,
//! then hand observations to the engine.

use crate::{effects, now_ms, writer::WriteCmd, App, Metrics};
use ho_logic::engine::Input;
use ho_logic::normalize::{boot_hex, normalize, FrameCtx};
use ho_logic::seq::{SeqTracker, SeqVerdict};
use ho_logic::timesync::OffsetEstimator;
use ho_protocol as p;
use ho_storage::{BatchMeta, InsertOutcome};
use rumqttc::QoS;
use std::collections::HashMap;
use std::time::Instant;

/// Per-node ingestion state.
#[derive(Default)]
pub struct NodeIngest {
    pub clock: OffsetEstimator,
    pub seq: SeqTracker,
    pub last_bssid: Option<String>,
    tokens: f64,
    last_refill: Option<Instant>,
}

#[derive(Default)]
pub struct IngestState {
    pub nodes: HashMap<String, NodeIngest>,
}

/// Parsed topic: `observatory/v1/{site}/nodes/{node}/{suffix...}`.
pub fn parse_topic<'a>(prefix: &str, topic: &'a str) -> Option<(&'a str, &'a str)> {
    let rest = topic.strip_prefix(prefix)?.strip_prefix("/nodes/")?;
    let (node, suffix) = rest.split_once('/')?;
    if !ho_domain::valid_id(node) {
        return None;
    }
    Some((node, suffix))
}

fn expected_kind(suffix: &str) -> Option<p::MsgKind> {
    Some(match suffix {
        "telemetry" => p::MsgKind::Telemetry,
        "events" => p::MsgKind::Events,
        "status" => p::MsgKind::Status,
        "capabilities" => p::MsgKind::Capabilities,
        "config/reported" => p::MsgKind::ConfigReported,
        _ => return None,
    })
}

fn reject(app: &App, node: Option<&str>, topic: &str, reason: &str, payload: &[u8]) {
    app.metrics.reject(reason);
    let _ = app.writer.try_send(WriteCmd::Dlq {
        at: now_ms(),
        node: node.map(String::from),
        topic: topic.chars().take(200).collect(),
        reason: reason.into(),
        head: payload.iter().take(32).copied().collect(),
    });
    tracing::debug!(reason, topic, "rejected message");
}

/// Handle one MQTT publish. Never panics; every failure is a counted rejection.
pub async fn handle(app: &App, topic: &str, payload: &[u8]) {
    let received_at = now_ms();
    let started = Instant::now();
    app.metrics.bytes_in.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
    let prefix = app.cfg.topic_prefix();
    let Some((node, suffix)) = parse_topic(&prefix, topic) else {
        return reject(app, None, topic, "bad_topic", &[]);
    };
    if !app.cfg.nodes.iter().any(|n| n.id.as_str() == node) {
        return reject(app, Some(node), topic, "unregistered_node", &[]);
    }
    // Last will: literal "offline" on the status topic.
    if suffix == "status" && payload == b"offline" {
        let fx = app.apply(Input::NodeStatus { node: node.into(), online: false, at: received_at });
        effects::handle(app, fx).await;
        return;
    }
    let Some(kind) = expected_kind(suffix) else {
        return reject(app, Some(node), topic, "unexpected_suffix", payload);
    };
    if payload.len() > p::MAX_FRAME_BYTES {
        return reject(app, Some(node), topic, "too_large", payload);
    }
    // Per-node frame budget: shed disposable telemetry first, keep critical events.
    let over_budget = {
        let Ok(mut st) = app.ingest.lock() else { return };
        let n = st.nodes.entry(node.to_string()).or_default();
        let rate = f64::from(app.cfg.server.max_frames_per_node_per_s.max(1));
        let now = Instant::now();
        let dt = n.last_refill.map_or(rate, |l| now.duration_since(l).as_secs_f64() * rate);
        n.tokens = (n.tokens + dt).min(rate * 2.0);
        n.last_refill = Some(now);
        if n.tokens >= 1.0 {
            n.tokens -= 1.0;
            false
        } else {
            true
        }
    };
    if over_budget && kind == p::MsgKind::Telemetry {
        Metrics::inc(&app.metrics.frames_shed);
        return reject(app, Some(node), topic, "rate_limited", &[]);
    }
    let frame = match p::decode_frame(payload) {
        Ok(f) => f,
        Err(e) => return reject(app, Some(node), topic, e.label(), payload),
    };
    let h = frame.header;
    if h.node_id != node {
        return reject(app, Some(node), topic, "envelope_topic_mismatch", payload);
    }
    if h.kind != kind {
        return reject(app, Some(node), topic, "kind_topic_mismatch", payload);
    }

    // Time + sequence bookkeeping (per node, per boot).
    let (verdict, uncertainty, obs) = {
        let Ok(mut st) = app.ingest.lock() else { return };
        let n = st.nodes.entry(node.to_string()).or_default();
        n.clock.observe(h.boot_id, h.sent_mono_ms, received_at);
        let verdict = n.seq.observe(h.boot_id, h.sequence);
        let ctx = FrameCtx { received_at, clock: &n.clock, current_bssid: n.last_bssid.clone() };
        let obs = normalize(&frame, &ctx);
        for o in &obs {
            if let ho_domain::ObsKind::Wifi(w) = &o.kind {
                if w.bssid.is_some() {
                    n.last_bssid = w.bssid.clone();
                }
            }
        }
        let unc = n.clock.map(h.sent_mono_ms, 0, received_at).uncertainty_ms;
        (verdict, unc, obs)
    };

    match kind {
        p::MsgKind::Capabilities => record_capabilities(app, node, received_at, &frame).await,
        p::MsgKind::ConfigReported => record_config_status(app, node, &frame).await,
        _ => {}
    }

    let meta = BatchMeta {
        site_id: app.cfg.site_id.to_string(),
        node_id: node.to_string(),
        boot_id: boot_hex(&h.boot_id),
        sequence: h.sequence,
        kind: h.kind as u8,
        flags: h.flags,
        received_at,
        sent_mono_ms: h.sent_mono_ms,
        config_revision: h.config_revision,
        record_count: frame.record_count,
        bytes: payload.len(),
        clock_uncertainty_ms: (uncertainty != u32::MAX).then_some(uncertainty),
    };
    // Durable commit precedes any acknowledgement.
    let outcome = match app.writer.insert_frame(meta, obs.clone()).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, node, "persist failed; not acknowledging");
            return reject(app, Some(node), topic, "persist_failed", &[]);
        }
    };
    if h.flags & p::flags::NEEDS_ACK != 0 {
        send_ack(app, node, h.boot_id, h.sequence).await;
    }
    match outcome {
        InsertOutcome::Duplicate => {
            Metrics::inc(&app.metrics.frames_duplicate);
            return;
        }
        InsertOutcome::Inserted(_) => Metrics::inc(&app.metrics.frames_accepted),
    }
    if verdict == SeqVerdict::Duplicate {
        return; // already processed in memory (should be caught by storage too)
    }
    app.metrics.observations.fetch_add(obs.len() as u64, std::sync::atomic::Ordering::Relaxed);
    let lag = obs.iter().map(|o| (received_at - o.time.observed_at).max(0)).max().unwrap_or(0) as u64;
    app.metrics.ingest_lag_ms_last.store(lag, std::sync::atomic::Ordering::Relaxed);
    app.metrics.ingest_lag_ms_max.fetch_max(lag, std::sync::atomic::Ordering::Relaxed);
    if !obs.is_empty() {
        let fx = app.apply(Input::Observations(obs));
        effects::handle(app, fx).await;
    }
    app.metrics
        .process_us_last
        .store(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX), std::sync::atomic::Ordering::Relaxed);
}

async fn send_ack(app: &App, node: &str, boot: [u8; 16], seq: u64) {
    let Some(client) = app.mqtt_client() else { return };
    match crate::desired::ack_frame(node, boot, seq, app.next_server_seq()) {
        Ok(f) => {
            let topic = format!("{}/nodes/{node}/ack", app.cfg.topic_prefix());
            if client.publish(topic, QoS::AtLeastOnce, false, f).await.is_ok() {
                Metrics::inc(&app.metrics.acks_sent);
            }
        }
        Err(e) => tracing::warn!(error = %e, "ack encode failed"),
    }
}

async fn record_capabilities(app: &App, node: &str, at: i64, frame: &p::Frame<'_>) {
    for r in frame.records() {
        if let p::Record::Capabilities(c) = r {
            let json = serde_json::json!({
                "chip": c.chip, "flash_kb": c.flash_kb, "ram_kb": c.ram_kb, "features": c.features,
                "fw_version": c.fw_version, "profile": c.profile, "max_payload": c.max_payload,
                "max_probe_targets": c.max_probe_targets, "max_tracked_bssids": c.max_tracked_bssids,
                "max_ble_devices": c.max_ble_devices,
                "ble": c.features & p::feature::BLE_OBSERVER != 0,
                "wifi_5ghz": c.features & p::feature::WIFI_5GHZ != 0,
                "ota": c.features & p::feature::OTA_AB != 0,
                "tls": c.features & p::feature::TLS != 0,
            });
            let _ = app
                .writer
                .send(WriteCmd::Capabilities {
                    node: node.into(),
                    at,
                    chip: c.chip.into(),
                    fw: c.fw_version.into(),
                    profile: c.profile.into(),
                    features: c.features,
                    flash_kb: c.flash_kb,
                    json: json.to_string(),
                })
                .await;
            // A (re)booted node gets its desired config (retained message also covers this).
            crate::jobs::publish_desired(app, node).await;
        }
    }
}

async fn record_config_status(app: &App, node: &str, frame: &p::Frame<'_>) {
    for r in frame.records() {
        if let p::Record::ConfigStatus(s) = r {
            let state = match s.state {
                p::ConfigState::Applied => "applied",
                p::ConfigState::Rejected => "rejected",
                p::ConfigState::Pending => "pending",
            };
            let _ = app.writer.send(WriteCmd::ConfigStatus { node: node.into(), revision: s.revision, state: state.into(), reason: s.reason }).await;
            if s.state == p::ConfigState::Rejected {
                tracing::warn!(node, revision = s.revision, reason = s.reason, "node rejected desired config");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_parsing_is_strict() {
        let pfx = "observatory/v1/home";
        assert_eq!(parse_topic(pfx, "observatory/v1/home/nodes/node-01/telemetry"), Some(("node-01", "telemetry")));
        assert_eq!(parse_topic(pfx, "observatory/v1/home/nodes/node-01/config/reported"), Some(("node-01", "config/reported")));
        assert_eq!(parse_topic(pfx, "observatory/v1/other/nodes/node-01/telemetry"), None);
        assert_eq!(parse_topic(pfx, "observatory/v1/home/nodes/Bad/telemetry"), None);
        assert_eq!(expected_kind("ack"), None, "nodes never publish acks");
    }
}
