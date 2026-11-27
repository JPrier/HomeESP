//! HTTP API `/api/v1` (spec §13.1). JSON with explicit units; consistent typed errors
//! `{code, message, request_id}`; bearer-token roles; bounded queries; SSE stream.

use crate::auth::Role;
use crate::{now_ms, writer::WriteCmd, App};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Typed API error.
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    fn bad(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", msg)
    }
    fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{what} not found"),
        )
    }
    fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "internal API error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let rid = format!("{:016x}", rand::random::<u64>());
        let mut r = (
            self.status,
            Json(json!({"code": self.code, "message": self.message, "request_id": rid})),
        )
            .into_response();
        if let Ok(v) = HeaderValue::from_str(&rid) {
            r.headers_mut().insert("x-request-id", v);
        }
        r
    }
}

type ApiResult = Result<Response, ApiError>;

fn require(app: &App, h: &HeaderMap, role: Role) -> Result<Role, ApiError> {
    match app.tokens.role(h) {
        None => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
        )),
        Some(r) if r < role => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "operator role required",
        )),
        Some(r) => Ok(r),
    }
}

fn ok(v: Value) -> ApiResult {
    Ok(Json(v).into_response())
}

fn iso(ms: i64) -> Value {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .map_or(Value::Null, Value::String)
}

pub fn router(app: App) -> Router {
    let api = Router::new()
        .route("/site/status", get(site_status))
        .route("/nodes", get(nodes))
        .route("/nodes/{id}", get(node))
        .route("/nodes/{id}/config", get(node_config).put(node_config_put))
        .route("/assets", get(assets))
        .route("/topology", get(topology))
        .route("/rooms", get(rooms))
        .route("/floorplans", get(rooms))
        .route("/devices", get(devices))
        .route("/devices/{id}", get(device).delete(device_revoke))
        .route("/locations/current", get(locations_current))
        .route("/locations/history", get(locations_history))
        .route("/metrics/query", get(metrics_query))
        .route("/metrics/catalog", get(metrics_catalog))
        .route("/coverage", get(coverage))
        .route("/incidents", get(incidents))
        .route("/incidents/{id}", get(incident))
        .route("/incidents/{id}/ack", post(incident_ack))
        .route("/incidents/{id}/notes", post(incident_note))
        .route("/recommendations", get(recommendations))
        .route("/diagnostics/jobs", get(diag_list).post(diag_run))
        .route("/diagnostics/dns", get(dns_matrix))
        .route("/notifications/test", post(notify_test))
        .route("/outbox", get(outbox))
        .route("/admin/config", get(admin_config).put(admin_config_put))
        .route("/audit", get(audit_route))
        .route("/events/stream", get(stream))
        .route("/openapi.json", get(openapi));
    let mut r = Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .route("/metrics", get(prometheus))
        .nest("/api/v1", api)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(256 * 1024))
        .with_state(app.clone());
    if let Some(dir) = &app.dashboard_dir {
        let index = dir.join("index.html");
        r = r.fallback_service(
            tower_http::services::ServeDir::new(dir)
                .fallback(tower_http::services::ServeFile::new(index)),
        );
    }
    r
}

async fn ready(State(app): State<App>) -> Response {
    let mqtt = app.mqtt_connected.load(Ordering::Relaxed) || !app.cfg.mqtt.enabled;
    let writer_ok = app.writer.capacity() > 0;
    let db_ok = app.reader().is_ok();
    let body = json!({"mqtt": mqtt, "writer": writer_ok, "database": db_ok});
    let code = if mqtt && writer_ok && db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

async fn prometheus(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let m = &app.metrics;
    let mut e = ho_integrations::metrics::Exposition::default();
    let c = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed) as f64;
    e.counter(
        "ho_frames_total",
        "Frames by result",
        &[("result", "accepted")],
        c(&m.frames_accepted),
    );
    e.counter(
        "ho_frames_total",
        "Frames by result",
        &[("result", "duplicate")],
        c(&m.frames_duplicate),
    );
    e.counter(
        "ho_frames_total",
        "Frames by result",
        &[("result", "shed")],
        c(&m.frames_shed),
    );
    if let Ok(r) = m.rejected.lock() {
        for (k, v) in r.iter() {
            e.counter(
                "ho_frames_rejected_total",
                "Rejected messages by reason",
                &[("reason", k)],
                *v as f64,
            );
        }
    }
    e.counter(
        "ho_ingress_bytes_total",
        "Payload bytes received",
        &[],
        c(&m.bytes_in),
    );
    e.counter("ho_acks_total", "Durable ACKs sent", &[], c(&m.acks_sent));
    e.counter(
        "ho_observations_total",
        "Observations processed",
        &[],
        c(&m.observations),
    );
    e.counter(
        "ho_notifications_total",
        "Notifications",
        &[("result", "sent")],
        c(&m.notifications_sent),
    );
    e.counter(
        "ho_notifications_total",
        "Notifications",
        &[("result", "failed")],
        c(&m.notifications_failed),
    );
    e.gauge(
        "ho_ingest_lag_ms",
        "Event-time to receipt lag of last frame",
        &[],
        c(&m.ingest_lag_ms_last),
    );
    e.gauge(
        "ho_process_us",
        "Processing time of last frame",
        &[],
        c(&m.process_us_last),
    );
    e.gauge(
        "ho_writer_queue_free",
        "Free writer queue slots",
        &[],
        app.writer.capacity() as f64,
    );
    e.gauge(
        "ho_mqtt_connected",
        "Broker session up",
        &[],
        f64::from(u8::from(app.mqtt_connected.load(Ordering::Relaxed))),
    );
    let snap = app.snapshot();
    for l in ["online", "stale", "missing", "unknown"] {
        let n = snap
            .nodes
            .iter()
            .filter(|x| {
                serde_json::to_value(x.liveness)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s == l))
                    .unwrap_or(false)
            })
            .count();
        e.gauge(
            "ho_nodes",
            "Nodes by liveness",
            &[("liveness", l)],
            n as f64,
        );
    }
    let active = snap
        .incidents
        .iter()
        .filter(|i| i.status != ho_logic::incidents::IncidentStatus::Resolved)
        .count();
    e.gauge(
        "ho_incidents_active",
        "Active incidents",
        &[],
        active as f64,
    );
    if let Ok(s) = app.echo_stats.lock() {
        e.counter(
            "ho_echo_total",
            "UDP echo requests",
            &[("result", "served")],
            s.0 as f64,
        );
        e.counter(
            "ho_echo_total",
            "UDP echo requests",
            &[("result", "rejected")],
            s.1 as f64,
        );
    }
    if let Ok(r) = app.reader() {
        if let Ok(sz) = r.size_bytes() {
            e.gauge("ho_db_bytes", "Database size", &[], sz as f64);
        }
    }
    Ok(([("content-type", "text/plain; version=0.0.4")], e.finish()).into_response())
}

async fn site_status(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let snap = app.snapshot();
    let score = ho_logic::recommend::score(&snap, app.cfg.thresholds.loss_min_samples);
    let active: Vec<_> = snap
        .incidents
        .iter()
        .filter(|i| i.status != ho_logic::incidents::IncidentStatus::Resolved)
        .collect();
    let m = &app.metrics;
    let counts = app
        .reader()
        .and_then(|r| r.counts().map_err(|e| e.to_string()))
        .unwrap_or(Value::Null);
    ok(json!({
        "site_id": app.cfg.site_id,
        "now": iso(now_ms()),
        "generated_at": iso(snap.at),
        "uptime_s": (now_ms() - app.started_at) / 1000,
        "ingestion_ok": snap.ingestion_ok,
        "mqtt_connected": app.mqtt_connected.load(Ordering::Relaxed),
        "nodes": snap.nodes.iter().map(|n| json!({"id": n.id, "liveness": n.liveness, "room": n.room,
            "rssi_dbm": n.state.rssi_dbm, "last_seen": n.state.last_seen.map(iso)})).collect::<Vec<_>>(),
        "targets": snap.targets,
        "active_incidents": active,
        "score": score,
        "ingest": {
            "frames_accepted": m.frames_accepted.load(Ordering::Relaxed),
            "frames_duplicate": m.frames_duplicate.load(Ordering::Relaxed),
            "frames_shed": m.frames_shed.load(Ordering::Relaxed),
            "lag_ms_last": m.ingest_lag_ms_last.load(Ordering::Relaxed),
            "lag_ms_max": m.ingest_lag_ms_max.load(Ordering::Relaxed),
            "rejected": m.rejected.lock().map(|r| r.clone()).unwrap_or_default(),
            "ble_discarded": snap.ble_discarded,
        },
        "storage": counts,
        "desired_revision": app.desired_revision.load(Ordering::Relaxed),
        "watchdog": app.watchdog_ok.lock().ok().and_then(|w| *w).map(|(t, ok)| json!({"at": iso(t), "ok": ok})),
    }))
}

async fn nodes(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let snap = app.snapshot();
    let db = app
        .reader()
        .and_then(|r| r.nodes().map_err(|e| e.to_string()))
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = app
        .cfg
        .nodes
        .iter()
        .map(|n| {
            let live = snap.nodes.iter().find(|x| x.id == n.id.as_str());
            let row = db.iter().find(|r| r["id"] == n.id.as_str()).cloned().unwrap_or(Value::Null);
            json!({"id": n.id, "room": n.room, "profile": n.profile, "position": n.position, "board": n.board,
                "liveness": live.map(|l| l.liveness), "state": live.map(|l| &l.state), "inventory": row})
        })
        .collect();
    ok(json!({"nodes": out}))
}

async fn node(State(app): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let Some(n) = app.cfg.node(&id) else {
        return Err(ApiError::not_found("node"));
    };
    let snap = app.snapshot();
    let r = app.reader().map_err(ApiError::internal)?;
    let inv = r
        .nodes()
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|x| x["id"] == id.as_str());
    ok(json!({
        "id": n.id, "config": n, "profile": app.cfg.profile_for(n),
        "live": snap.nodes.iter().find(|x| x.id == id),
        "targets": snap.targets.iter().filter(|t| t.vantage == id).collect::<Vec<_>>(),
        "inventory": inv,
        "health": r.node_health_latest(&id).map_err(ApiError::internal)?,
        "events": r.node_events(&id, 50).map_err(ApiError::internal)?,
        "latest_scan": r.latest_scan(&id).map_err(ApiError::internal)?,
    }))
}

async fn node_config(State(app): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let Some(n) = app.cfg.node(&id) else {
        return Err(ApiError::not_found("node"));
    };
    let rev = app.desired_revision.load(Ordering::Relaxed);
    let inv = app
        .reader()
        .and_then(|r| r.nodes().map_err(|e| e.to_string()))
        .map_err(ApiError::internal)?;
    let row = inv
        .into_iter()
        .find(|x| x["id"] == id.as_str())
        .unwrap_or(Value::Null);
    ok(
        json!({"node": id, "desired": {"revision": rev, "profile": app.cfg.profile_for(n),
        "probe_targets": app.cfg.probe_targets.iter().filter(|t| t.nodes.is_empty() || t.nodes.contains(&n.id)).collect::<Vec<_>>()},
        "reported": {"revision": row["applied_revision"], "state": row["config_state"], "reason": row["config_reason"]}}),
    )
}

/// Re-publish desired config to a node (the desired content itself is edited via
/// `/admin/config`). Requires `If-Match: <current revision>` to avoid lost updates.
async fn node_config_put(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    if app.cfg.node(&id).is_none() {
        return Err(ApiError::not_found("node"));
    }
    let rev = app.desired_revision.load(Ordering::Relaxed);
    let im = h
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    if im.as_deref() != Some(rev.to_string().as_str()) {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "revision_mismatch",
            format!("If-Match must equal current revision {rev}"),
        ));
    }
    crate::jobs::publish_desired(&app, &id).await;
    log_audit(
        &app,
        role,
        "node.config.republish",
        Some(&id),
        json!({"revision": rev}),
    )
    .await;
    ok(
        json!({"node": id, "revision": rev, "published": app.mqtt_connected.load(Ordering::Relaxed)}),
    )
}

async fn log_audit(app: &App, role: Role, action: &str, target: Option<&str>, detail: Value) {
    let _ = app
        .writer
        .send(WriteCmd::Audit {
            at: now_ms(),
            actor: format!("{role:?}").to_lowercase(),
            action: action.into(),
            target: target.map(String::from),
            detail,
        })
        .await;
}

async fn assets(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    ok(json!({"assets": app.cfg.assets, "radios": app.cfg.radios}))
}

async fn topology(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let snap = app.snapshot();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for a in &app.cfg.assets {
        let targets: Vec<_> = snap
            .targets
            .iter()
            .filter(|t| t.asset.as_deref() == Some(a.id.as_str()))
            .collect();
        let health = targets.iter().map(|t| t.health).max_by_key(|h| match h {
            ho_domain::Health::Failed => 5,
            ho_domain::Health::Degraded => 4,
            ho_domain::Health::Recovering => 3,
            ho_domain::Health::Healthy => 2,
            ho_domain::Health::Maintenance => 1,
            ho_domain::Health::Unknown => 0,
        });
        let in_incident: Vec<&str> = snap
            .incidents
            .iter()
            .filter(|i| {
                i.status != ho_logic::incidents::IncidentStatus::Resolved
                    && i.hypothesis.scope_assets.iter().any(|s| s == a.id.as_str())
            })
            .map(|i| i.id.as_str())
            .collect();
        nodes.push(json!({"id": a.id, "kind": a.kind, "name": a.name, "critical": a.critical,
            "health": health.unwrap_or(ho_domain::Health::Unknown), "incidents": in_incident, "evidence": targets}));
        for p in &a.parents {
            edges.push(json!({"from": a.id, "to": p, "type": "hard", "source": "configured"}));
        }
        for p in &a.redundant_parents {
            edges.push(json!({"from": a.id, "to": p, "type": "redundant", "source": "configured"}));
        }
    }
    for n in &snap.nodes {
        nodes.push(json!({"id": n.id, "kind": "node", "liveness": n.liveness, "rssi_dbm": n.state.rssi_dbm}));
        if let Some(ap) = &n.state.ap {
            edges.push(
                json!({"from": n.id, "to": ap, "type": "association", "source": "observed",
                "last_seen": n.state.last_seen.map(iso)}),
            );
        }
    }
    ok(json!({"nodes": nodes, "edges": edges}))
}

async fn rooms(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    ok(
        json!({"floors": app.cfg.floors, "rooms": app.cfg.rooms, "room_edges": app.cfg.room_edges,
        "nodes": app.cfg.nodes.iter().map(|n| json!({"id": n.id, "room": n.room, "position": n.position})).collect::<Vec<_>>()}),
    )
}

async fn devices(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    // Matcher material is protected: never returned by the API.
    let snap = app.snapshot();
    ok(
        json!({"location_enabled": app.cfg.privacy.location_enabled, "devices": app.cfg.devices.iter().map(|d| json!({
        "id": d.id, "kind": d.kind, "name": d.name, "consent": d.consent, "owner": d.owner,
        "matcher_type": match d.matcher { ho_domain::MatcherConf::Ibeacon { .. } => "ibeacon" },
        "location": snap.locations.iter().find(|l| l.device_id == d.id.as_str()),
    })).collect::<Vec<_>>()}),
    )
}

async fn device(State(app): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let Some(d) = app.cfg.devices.iter().find(|d| d.id.as_str() == id) else {
        return Err(ApiError::not_found("device"));
    };
    let snap = app.snapshot();
    ok(
        json!({"id": d.id, "kind": d.kind, "name": d.name, "consent": d.consent,
        "location": snap.locations.iter().find(|l| l.device_id == id)}),
    )
}

/// Revoke consent: stop tracking immediately, purge live/derived/historical data and
/// expire the HA entities. (Remove the device from the config file to make it permanent.)
async fn device_revoke(State(app): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    if !app.cfg.devices.iter().any(|d| d.id.as_str() == id) {
        return Err(ApiError::not_found("device"));
    }
    let fx = app.apply(ho_logic::engine::Input::RevokeDevice {
        device_id: id.clone(),
        at: now_ms(),
    });
    crate::effects::handle(&app, fx).await;
    if let Some(c) = app.mqtt_client() {
        let oid = id.replace('-', "_");
        for p in ho_integrations::ha::removal(
            &app.cfg,
            &[
                format!("device_{oid}_current_room"),
                format!("device_{oid}_location_confidence"),
            ],
        ) {
            let _ = c
                .publish(p.topic, rumqttc::QoS::AtLeastOnce, true, p.payload)
                .await;
        }
    }
    log_audit(&app, role, "device.revoke", Some(&id), json!({})).await;
    ok(json!({"device": id, "revoked": true, "purged": true}))
}

async fn locations_current(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    if !app.cfg.privacy.location_enabled {
        return ok(json!({"location_enabled": false, "locations": []}));
    }
    ok(json!({"location_enabled": true, "locations": app.snapshot().locations}))
}

#[derive(Deserialize)]
struct HistQ {
    device: Option<String>,
    hours: Option<i64>,
    limit: Option<usize>,
}

async fn locations_history(
    State(app): State<App>,
    h: HeaderMap,
    Query(q): Query<HistQ>,
) -> ApiResult {
    require(&app, &h, Role::Operator)?; // location history is sensitive
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let rows = app
        .reader()
        .and_then(|r| {
            r.location_history(
                q.device.as_deref(),
                now_ms() - hours * 3_600_000,
                q.limit.unwrap_or(500).min(5000),
            )
            .map_err(|e| e.to_string())
        })
        .map_err(ApiError::internal)?;
    ok(json!({"history": rows}))
}

#[derive(Deserialize)]
struct MetricsQ {
    target: String,
    vantage: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    hours: Option<i64>,
    max_points: Option<usize>,
}

async fn metrics_query(
    State(app): State<App>,
    h: HeaderMap,
    Query(q): Query<MetricsQ>,
) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    // Allowlist: only configured/built-in targets.
    let known = app
        .cfg
        .probe_targets
        .iter()
        .any(|t| t.id.as_str() == q.target)
        || app
            .cfg
            .central_checks
            .iter()
            .any(|t| t.id.as_str() == q.target)
        || ho_logic::engine::BUILTIN_NODE_TARGETS.contains(&q.target.as_str());
    if !known {
        return Err(ApiError::bad("unknown target"));
    }
    let now = now_ms(); // relative times resolved once at request start
    let to = q.to.unwrap_or(now).min(now);
    let from = q
        .from
        .unwrap_or_else(|| to - q.hours.unwrap_or(6).clamp(1, 24 * 365) * 3_600_000);
    if from >= to || to - from > 400 * 86_400_000 {
        return Err(ApiError::bad("invalid range (max 400 days)"));
    }
    let series = app
        .reader()
        .and_then(|r| {
            r.probe_series(
                &q.target,
                q.vantage.as_deref(),
                from,
                to,
                q.max_points.unwrap_or(500),
            )
            .map_err(|e| e.to_string())
        })
        .map_err(ApiError::internal)?;
    ok(json!({"from": from, "to": to, "units": {"rtt": "ms", "loss": "percent"}, "series": series}))
}

async fn metrics_catalog(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let c = app
        .reader()
        .and_then(|r| {
            r.probe_catalog(now_ms() - 7 * 86_400_000)
                .map_err(|e| e.to_string())
        })
        .map_err(ApiError::internal)?;
    ok(
        json!({"series": c.into_iter().map(|(t, v)| json!({"target": t, "vantage": v})).collect::<Vec<_>>()}),
    )
}

async fn coverage(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let anchors = app
        .reader()
        .and_then(|r| r.coverage(now_ms() - 3_600_000).map_err(|e| e.to_string()))
        .map_err(ApiError::internal)?;
    let positioned: Vec<Value> = anchors
        .into_iter()
        .map(|mut a| {
            let node = a["node"].as_str().unwrap_or_default().to_string();
            let n = app.cfg.node(&node);
            a["position"] = json!(n.and_then(|n| n.position));
            a["room"] = json!(n.and_then(|n| n.room.clone()));
            a["ap"] =
                json!(app
                    .cfg
                    .radios
                    .iter()
                    .find(|r| Some(r.bssid.to_lowercase())
                        == a["bssid"].as_str().map(str::to_lowercase))
                    .map(|r| &r.ap));
            a["band"] = json!("2.4");
            a
        })
        .collect();
    ok(
        json!({"anchors": positioned, "note": "measured anchors only; interpolation is a visualization with explicit uncertainty"}),
    )
}

#[derive(Deserialize)]
struct IncQ {
    status: Option<String>,
    limit: Option<usize>,
}

async fn incidents(State(app): State<App>, h: HeaderMap, Query(q): Query<IncQ>) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    if let Some(s) = &q.status {
        if !["open", "recovering", "resolved"].contains(&s.as_str()) {
            return Err(ApiError::bad("status must be open|recovering|resolved"));
        }
    }
    let rows = app
        .reader()
        .and_then(|r| {
            r.incidents(q.status.as_deref(), q.limit.unwrap_or(100).min(1000))
                .map_err(|e| e.to_string())
        })
        .map_err(ApiError::internal)?;
    ok(json!({"incidents": rows}))
}

async fn incident(State(app): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let r = app.reader().map_err(ApiError::internal)?;
    let inc = r
        .incidents(None, 5000)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|i| i["id"] == id.as_str());
    let Some(inc) = inc else {
        return Err(ApiError::not_found("incident"));
    };
    ok(json!({"incident": inc, "timeline": r.incident_events(&id).map_err(ApiError::internal)?}))
}

async fn incident_ack(State(app): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    let found = app
        .writer
        .call(|reply| WriteCmd::Ack {
            id: id.clone(),
            reply,
        })
        .await
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found("incident"));
    }
    app.apply(ho_logic::engine::Input::Acknowledge {
        incident_id: id.clone(),
        at: now_ms(),
    });
    log_audit(&app, role, "incident.ack", Some(&id), json!({})).await;
    ok(json!({"id": id, "acknowledged": true}))
}

#[derive(Deserialize)]
struct Note {
    note: String,
}

async fn incident_note(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(b): Json<Note>,
) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    if b.note.is_empty() || b.note.len() > 2000 {
        return Err(ApiError::bad("note must be 1..2000 chars"));
    }
    let actor = format!("{role:?}").to_lowercase();
    let found = app
        .writer
        .call(|reply| WriteCmd::Note {
            id: id.clone(),
            at: now_ms(),
            actor,
            note: b.note.clone(),
            reply,
        })
        .await
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found("incident"));
    }
    ok(json!({"id": id, "noted": true}))
}

async fn recommendations(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let snap = app.snapshot();
    ok(
        json!({"advisory_only": true, "recommendations": ho_logic::recommend::recommendations(&snap)}),
    )
}

/// DNS matrix: every DNS target by vantage with outcome breakdown.
async fn dns_matrix(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let snap = app.snapshot();
    let rows: Vec<Value> = snap
        .targets
        .iter()
        .filter(|t| t.kind == "dns")
        .map(|t| json!({"vantage": t.vantage, "target": t.target, "health": t.health, "reason": t.reason, "stats": t.stats,
            "wired": t.vantage == "central"}))
        .collect();
    ok(json!({"matrix": rows}))
}

#[derive(Deserialize)]
struct DiagReq {
    job: String,
    check: Option<String>,
}

const ALLOWED_JOBS: [&str; 2] = ["check-now", "dns-matrix-now"];

async fn diag_list(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    ok(
        json!({"allowed_jobs": ALLOWED_JOBS, "note": "only allowlisted bounded checks of configured targets; no arbitrary hosts"}),
    )
}

/// Run allowlisted bounded diagnostics immediately (configured checks only).
async fn diag_run(State(app): State<App>, h: HeaderMap, Json(b): Json<DiagReq>) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    let checks: Vec<ho_domain::CentralCheck> = match b.job.as_str() {
        "check-now" => {
            let id = b.check.ok_or_else(|| ApiError::bad("check is required"))?;
            let c = app
                .cfg
                .central_checks
                .iter()
                .find(|c| c.id.as_str() == id)
                .cloned();
            vec![c.ok_or_else(|| {
                ApiError::bad("unknown check (must be a configured central check)")
            })?]
        }
        "dns-matrix-now" => app
            .cfg
            .central_checks
            .iter()
            .filter(|c| c.kind == ho_domain::ProbeKindConf::Dns)
            .cloned()
            .collect(),
        _ => return Err(ApiError::bad("job not allowlisted")),
    };
    log_audit(
        &app,
        role,
        "diagnostics.run",
        Some(&b.job),
        json!({"checks": checks.len()}),
    )
    .await;
    let mut results = Vec::new();
    for c in checks.iter().take(16) {
        results.push(ho_collectors::run_check(c).await);
    }
    ok(json!({"job": b.job, "results": results}))
}

async fn notify_test(State(app): State<App>, h: HeaderMap) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    let at = now_ms();
    let msg = ho_integrations::notify::Message {
        incident_id: format!("test-{at}"),
        event: "test".into(),
        episode: 1,
        severity: ho_domain::Severity::Info,
        title: "Home Observatory test notification".into(),
        body: "This is an explicit, labeled test. No incident is open.".into(),
        at,
        test: true,
    };
    let payload = serde_json::to_string(&msg).map_err(ApiError::internal)?;
    let rows: Vec<_> = app
        .cfg
        .notifications
        .notifiers
        .iter()
        .map(|n| {
            (
                format!("{}|test|1|{}", msg.incident_id, n.id),
                n.id.clone(),
                payload.clone(),
                at,
                false,
            )
        })
        .collect();
    let n = rows.len();
    app.writer
        .send(WriteCmd::Derived {
            incidents: vec![],
            events: vec![],
            outbox: rows,
            locations: vec![],
            checkpoint: None,
        })
        .await
        .map_err(ApiError::internal)?;
    log_audit(
        &app,
        role,
        "notifications.test",
        None,
        json!({"notifiers": n}),
    )
    .await;
    ok(json!({"queued": n, "note": "delivery is confirmed only when the outbox shows status=sent"}))
}

async fn outbox(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Viewer)?;
    let rows = app
        .reader()
        .and_then(|r| r.outbox_list(None, 200).map_err(|e| e.to_string()))
        .map_err(ApiError::internal)?;
    ok(json!({"outbox": rows}))
}

async fn admin_config(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Operator)?;
    // The config contains no secrets (only file paths to them).
    let yaml = serde_yaml::to_string(&app.cfg).map_err(ApiError::internal)?;
    let rev = app
        .reader()
        .ok()
        .and_then(|r| r.active_config_revision().ok().flatten());
    ok(
        json!({"revision": rev.as_ref().map(|r| r.0), "sha256": rev.map(|r| r.1), "config": app.cfg, "yaml": yaml}),
    )
}

#[derive(Deserialize)]
struct ConfigPut {
    yaml: String,
    #[serde(default)]
    dry_run: bool,
}

/// Validate (dry-run) or apply a new configuration. Applying writes the config file
/// atomically, records a revision + audit, and requires a restart to take effect.
async fn admin_config_put(
    State(app): State<App>,
    h: HeaderMap,
    Json(b): Json<ConfigPut>,
) -> ApiResult {
    let role = require(&app, &h, Role::Operator)?;
    if b.yaml.len() > 200_000 {
        return Err(ApiError::bad("config too large"));
    }
    let parsed: Result<ho_domain::SiteConfig, _> = serde_yaml::from_str(&b.yaml);
    let new_cfg =
        match parsed {
            Ok(c) => c,
            Err(e) => return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({"code": "invalid", "issues": [{"path": "", "message": e.to_string()}]}),
                ),
            )
                .into_response()),
        };
    // Security-sensitive sections (secret file paths, broker, notifier endpoints,
    // integrations, watchdog) can only be changed on the host, never over HTTP.
    let locked = locked_section_changes(&app.cfg, &new_cfg);
    if !locked.is_empty() {
        let issues: Vec<Value> = locked
            .iter()
            .map(|s| json!({"path": s, "message": "this section is immutable via the API; edit the file on the host"}))
            .collect();
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"code": "locked_section", "issues": issues})),
        )
            .into_response());
    }
    let issues = new_cfg.validate();
    if !issues.is_empty() {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"code": "invalid", "issues": issues})),
        )
            .into_response());
    }
    if b.dry_run {
        return ok(json!({"valid": true, "dry_run": true}));
    }
    let current = app
        .reader()
        .ok()
        .and_then(|r| r.active_config_revision().ok().flatten());
    let im = h
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    if im != current.as_ref().map(|c| c.0.to_string()) {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "revision_mismatch",
            "If-Match must equal the current config revision",
        ));
    }
    let Some(path) = &app.config_path else {
        return Err(ApiError::bad(
            "server was started without a config file path",
        ));
    };
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, &b.yaml).map_err(ApiError::internal)?;
    std::fs::rename(&tmp, path).map_err(ApiError::internal)?;
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b.yaml.as_bytes()));
    let rev = app
        .writer
        .call(|reply| WriteCmd::SaveConfigRevision {
            at: now_ms(),
            actor: format!("{role:?}").to_lowercase(),
            sha: sha.clone(),
            yaml: b.yaml.clone(),
            reply,
        })
        .await
        .map_err(ApiError::internal)?;
    log_audit(
        &app,
        role,
        "config.apply",
        None,
        json!({"revision": rev, "sha256": sha}),
    )
    .await;
    ok(json!({"applied": true, "revision": rev, "restart_required": true}))
}

/// Names of security-sensitive config sections that differ between `a` and `b`.
pub fn locked_section_changes(
    a: &ho_domain::SiteConfig,
    b: &ho_domain::SiteConfig,
) -> Vec<&'static str> {
    let mut v = Vec::new();
    let differ = |x: &dyn erased::Ser, y: &dyn erased::Ser| x.json() != y.json();
    if differ(&a.server, &b.server) {
        v.push("server");
    }
    if differ(&a.mqtt, &b.mqtt) {
        v.push("mqtt");
    }
    if differ(&a.notifications.notifiers, &b.notifications.notifiers) {
        v.push("notifications.notifiers");
    }
    if differ(&a.integrations, &b.integrations) {
        v.push("integrations");
    }
    if differ(&a.watchdog, &b.watchdog) {
        v.push("watchdog");
    }
    if a.site_id != b.site_id {
        v.push("site_id");
    }
    v
}

mod erased {
    pub trait Ser {
        fn json(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
        }
    }
}

async fn audit_list(app: &App) -> Result<Value, ApiError> {
    let rows = app
        .reader()
        .and_then(|r| r.audit_list(200).map_err(|e| e.to_string()))
        .map_err(ApiError::internal)?;
    Ok(json!({"audit": rows}))
}

async fn audit_route(State(app): State<App>, h: HeaderMap) -> ApiResult {
    require(&app, &h, Role::Operator)?;
    ok(audit_list(&app).await?)
}

/// Server-sent events of sanitized state changes (no per-advertisement data).
async fn stream(
    State(app): State<App>,
    h: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    require(&app, &h, Role::Viewer)?;
    let mut rx = app.events.subscribe();
    let location_ok = app.cfg.privacy.location_enabled;
    let s = async_stream::stream! {
        yield Ok(Event::default().event("hello").data("{}"));
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if !location_ok && msg.contains("\"effect\":\"location\"") { continue; }
                    yield Ok(Event::default().event("state").data(msg));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // Bounded buffer: tell the client to refetch a snapshot.
                    yield Ok(Event::default().event("lagged").data(n.to_string()));
                }
                Err(_) => break,
            }
        }
    };
    Ok(Sse::new(s).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

async fn openapi() -> Response {
    (
        [("content-type", "application/json")],
        include_str!("../../../docs/openapi.json"),
    )
        .into_response()
}
