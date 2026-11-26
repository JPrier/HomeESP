//! Perform engine effects: persist derived state + outbox atomically, fan out to SSE.

use crate::{writer::WriteCmd, App};
use ho_integrations::notify::Message;
use ho_logic::engine::Effect;
use ho_logic::incidents::Incident;

/// Build outbox rows for a notification according to configured routes.
fn route(app: &App, n: &ho_logic::engine::Notification) -> Vec<crate::writer::OutboxRow> {
    let msg = Message {
        incident_id: n.incident_id.clone(),
        event: n.event.clone(),
        episode: n.episode,
        severity: n.severity,
        title: n.title.clone(),
        body: n.body.clone(),
        at: n.at,
        test: false,
    };
    let payload = serde_json::to_string(&msg).unwrap_or_default();
    app.cfg
        .notifications
        .routes
        .iter()
        .filter(|r| n.severity >= r.min_severity && (n.event != "resolved" || r.send_recovery))
        .map(|r| {
            (
                format!("{}|{}|{}|{}", n.incident_id, n.event, n.episode, r.notifier),
                r.notifier.clone(),
                payload.clone(),
                n.at,
                n.suppressed,
            )
        })
        .collect()
}

pub async fn handle(app: &App, fx: Vec<Effect>) {
    if fx.is_empty() {
        return;
    }
    let mut events = Vec::new();
    let mut outbox = Vec::new();
    let mut locations = Vec::new();
    let mut purge = Vec::new();
    for e in &fx {
        if let Ok(s) = serde_json::to_string(e) {
            let _ = app.events.send(s);
        }
        match e {
            Effect::Incident(ev) => events.push(ev.clone()),
            Effect::Notify(n) => outbox.extend(route(app, n)),
            Effect::Location(l) => locations.push(l.clone()),
            Effect::LocationPurged { device_id, .. } => purge.push(device_id.clone()),
            Effect::NodeLiveness { node, liveness, .. } => tracing::info!(node, ?liveness, "node liveness"),
            Effect::TargetHealth { vantage, target, health, reason, .. } => {
                tracing::info!(vantage, target, health = health.as_str(), reason, "target health")
            }
            Effect::BleDiscarded { .. } => {}
        }
    }
    if !events.is_empty() || !outbox.is_empty() || !locations.is_empty() {
        let incidents: Vec<Incident> = {
            let keys: std::collections::BTreeSet<&str> = events.iter().map(|e| e.key.as_str()).collect();
            app.with_engine(|eng| eng.snapshot().incidents.into_iter().filter(|i| keys.contains(i.key.as_str())).collect())
        };
        let counter = app.with_engine(|e| e.incident_counter());
        for ev in &events {
            tracing::warn!(incident = ev.incident_id, kind = ev.kind.as_str(), title = ev.title, "incident");
        }
        let _ = app
            .writer
            .send(WriteCmd::Derived {
                incidents,
                events,
                outbox,
                locations,
                checkpoint: Some(("incident_counter".into(), counter.to_string())),
            })
            .await;
    }
    for d in purge {
        let r = app.writer.call(|reply| WriteCmd::Purge { device: d.clone(), reply }).await;
        tracing::info!(device = d, result = ?r, "purged device data");
    }
}
