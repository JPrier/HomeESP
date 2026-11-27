//! `--simulate`: drive the real ingestion path from the deterministic simulator.
//! No network probing happens in this mode (central checks are simulated too), so it
//! is safe on any network. A scripted fault cycle makes incidents visible in the UI.

use crate::{ingest, jobs, now_ms, App};
use ho_simulator::World;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Fault script: (minute offset in a 20-minute cycle, description, action).
fn apply_phase(w: &mut World, minute: u64) -> Option<&'static str> {
    match minute {
        4 => {
            w.net.ap_down = Some("ap-living".into());
            w.roam("node-02", "ap-office");
            w.roam("node-03", "ap-office");
            Some("AP outage: ap-living down, two nodes roam")
        }
        7 => {
            w.net.ap_down = None;
            w.roam("node-02", "ap-living");
            w.roam("node-03", "ap-living");
            Some("AP recovered")
        }
        10 => {
            w.net.dns_down = true;
            Some("resolver failure (SERVFAIL)")
        }
        13 => {
            w.net.dns_down = false;
            Some("resolver recovered")
        }
        16 => {
            w.place("phone-1", Some("office"));
            Some("phone moves to the office")
        }
        19 => {
            w.place("phone-1", Some("living"));
            Some("phone returns to the living room")
        }
        _ => None,
    }
}

pub async fn run(app: App, seed: u64, cancel: CancellationToken) {
    let mut w = World::new(app.cfg.clone(), seed);
    let model = w.calibrated_model("phone-1");
    app.apply(ho_logic::engine::Input::ActivateModel(model));
    w.place("phone-1", Some("living"));
    w.place("tag-1", Some("kitchen"));
    w.h.record = true;
    w.record_central = true;
    let started = std::time::Instant::now();
    let mut last_minute = u64::MAX;
    let mut iv = tokio::time::interval(Duration::from_millis(250));
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::warn!("SIMULATION MODE: all node data is synthetic; no real network is probed");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = iv.tick() => {}
        }
        let minute = (started.elapsed().as_secs() / 60) % 20;
        if minute != last_minute {
            last_minute = minute;
            if let Some(what) = apply_phase(&mut w, minute) {
                tracing::info!(minute, what, "simulation phase");
            }
        }
        w.run(250);
        let frames: Vec<_> = w.h.recorded.drain(..).collect();
        for f in frames {
            if let Some(b) = ho_simulator::hex_decode(&f.hex) {
                ingest::handle(&app, &f.topic, &b).await;
            }
        }
        let central: Vec<_> = w.central_log.drain(..).collect();
        for (seq, p) in central {
            jobs::record_central(&app, "sim-central", seq, now_ms(), p).await;
        }
    }
}
