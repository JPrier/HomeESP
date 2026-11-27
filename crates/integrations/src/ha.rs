//! Home Assistant MQTT discovery (spec §14.1).
//!
//! Stable `unique_id`s, retained discovery config, per-entity availability, and
//! explicit removal (empty retained payload). State is derived and sanitized; room
//! location is only published when `privacy.publish_location_to_ha` is enabled.

use ho_domain::{HomeAssistant, LocationState, NodeLiveness, SiteConfig};
use ho_logic::engine::EngineSnapshot;
use ho_logic::recommend::Score;
use serde_json::json;

/// One MQTT publication.
#[derive(Debug, Clone, PartialEq)]
pub struct Publish {
    pub topic: String,
    pub payload: String,
    pub retain: bool,
}

#[derive(Debug, Clone)]
struct Entity {
    component: &'static str,
    object_id: String,
    name: String,
    unit: Option<&'static str>,
    device_class: Option<&'static str>,
    state_class: Option<&'static str>,
    icon: Option<&'static str>,
}

fn entities(cfg: &SiteConfig) -> Vec<Entity> {
    let mut v = vec![
        Entity {
            component: "sensor",
            object_id: "network_dns_p95_latency".into(),
            name: "DNS p95 latency".into(),
            unit: Some("ms"),
            device_class: Some("duration"),
            state_class: Some("measurement"),
            icon: None,
        },
        Entity {
            component: "sensor",
            object_id: "network_wireless_p95_latency".into(),
            name: "Wireless p95 latency".into(),
            unit: Some("ms"),
            device_class: Some("duration"),
            state_class: Some("measurement"),
            icon: None,
        },
        Entity {
            component: "sensor",
            object_id: "network_packet_loss".into(),
            name: "Packet loss".into(),
            unit: Some("%"),
            device_class: None,
            state_class: Some("measurement"),
            icon: Some("mdi:lan-disconnect"),
        },
        Entity {
            component: "sensor",
            object_id: "network_health_score".into(),
            name: "Network health score".into(),
            unit: None,
            device_class: None,
            state_class: Some("measurement"),
            icon: Some("mdi:gauge"),
        },
        Entity {
            component: "binary_sensor",
            object_id: "network_congested".into(),
            name: "Network congested".into(),
            unit: None,
            device_class: Some("problem"),
            state_class: None,
            icon: None,
        },
        Entity {
            component: "binary_sensor",
            object_id: "dns_available".into(),
            name: "DNS available".into(),
            unit: None,
            device_class: Some("connectivity"),
            state_class: None,
            icon: None,
        },
    ];
    for n in &cfg.nodes {
        let id = n.id.as_str().replace('-', "_");
        v.push(Entity {
            component: "binary_sensor",
            object_id: format!("{id}_online"),
            name: format!("{} online", n.id),
            unit: None,
            device_class: Some("connectivity"),
            state_class: None,
            icon: None,
        });
        v.push(Entity {
            component: "sensor",
            object_id: format!("{id}_wifi_rssi"),
            name: format!("{} Wi-Fi RSSI", n.id),
            unit: Some("dBm"),
            device_class: Some("signal_strength"),
            state_class: Some("measurement"),
            icon: None,
        });
    }
    for a in cfg
        .assets
        .iter()
        .filter(|a| a.kind == ho_domain::AssetKind::AccessPoint)
    {
        let id = a.id.as_str().replace('-', "_");
        v.push(Entity {
            component: "binary_sensor",
            object_id: format!("{id}_available"),
            name: format!("{} available", a.id),
            unit: None,
            device_class: Some("connectivity"),
            state_class: None,
            icon: None,
        });
    }
    if cfg.privacy.location_enabled && cfg.privacy.publish_location_to_ha {
        for d in cfg.devices.iter().filter(|d| d.consent) {
            let id = d.id.as_str().replace('-', "_");
            v.push(Entity {
                component: "sensor",
                object_id: format!("device_{id}_current_room"),
                name: format!("{} room", d.name),
                unit: None,
                device_class: None,
                state_class: None,
                icon: Some("mdi:map-marker"),
            });
            v.push(Entity {
                component: "sensor",
                object_id: format!("device_{id}_location_confidence"),
                name: format!("{} location confidence", d.name),
                unit: Some("%"),
                device_class: None,
                state_class: Some("measurement"),
                icon: None,
            });
        }
    }
    v
}

fn state_topic(ha: &HomeAssistant, object_id: &str) -> String {
    format!("{}/{object_id}/state", ha.state_prefix)
}
fn avail_topic(ha: &HomeAssistant, object_id: &str) -> String {
    format!("{}/{object_id}/availability", ha.state_prefix)
}
fn site_avail_topic(ha: &HomeAssistant) -> String {
    format!("{}/availability", ha.state_prefix)
}

/// Retained discovery configs for every entity (republish on HA birth).
pub fn discovery(cfg: &SiteConfig) -> Vec<Publish> {
    let ha = &cfg.home_assistant;
    entities(cfg)
        .into_iter()
        .map(|e| {
            let uid = format!("observatory_{}_{}", cfg.site_id, e.object_id);
            let mut c = json!({
                "name": e.name,
                "unique_id": uid,
                "object_id": e.object_id,
                "state_topic": state_topic(ha, &e.object_id),
                "availability_mode": "all",
                "availability": [
                    {"topic": site_avail_topic(ha)},
                    {"topic": avail_topic(ha, &e.object_id)}
                ],
                "device": {
                    "identifiers": [format!("observatory_{}", cfg.site_id)],
                    "name": "Home Observatory",
                    "manufacturer": "Home Observatory",
                    "model": "observatory-server"
                }
            });
            if let Some(obj) = c.as_object_mut() {
                if let Some(u) = e.unit {
                    obj.insert("unit_of_measurement".into(), json!(u));
                }
                if let Some(d) = e.device_class {
                    obj.insert("device_class".into(), json!(d));
                }
                if let Some(s) = e.state_class {
                    obj.insert("state_class".into(), json!(s));
                }
                if let Some(i) = e.icon {
                    obj.insert("icon".into(), json!(i));
                }
                if e.component == "binary_sensor" {
                    obj.insert("payload_on".into(), json!("ON"));
                    obj.insert("payload_off".into(), json!("OFF"));
                }
            }
            Publish {
                topic: format!("{}/{}/{}/config", ha.discovery_prefix, e.component, uid),
                payload: c.to_string(),
                retain: true,
            }
        })
        .collect()
}

/// Empty retained payloads that delete entities (e.g. revoked device).
pub fn removal(cfg: &SiteConfig, object_ids: &[String]) -> Vec<Publish> {
    let ha = &cfg.home_assistant;
    let mut v = Vec::new();
    for oid in object_ids {
        let uid = format!("observatory_{}_{oid}", cfg.site_id);
        for comp in ["sensor", "binary_sensor"] {
            v.push(Publish {
                topic: format!("{}/{comp}/{uid}/config", ha.discovery_prefix),
                payload: String::new(),
                retain: true,
            });
        }
        v.push(Publish {
            topic: state_topic(ha, oid),
            payload: String::new(),
            retain: true,
        });
        v.push(Publish {
            topic: avail_topic(ha, oid),
            payload: String::new(),
            retain: true,
        });
    }
    v
}

/// Site-level availability (online while the server runs; LWT should set offline).
pub fn site_availability(cfg: &SiteConfig, online: bool) -> Publish {
    Publish {
        topic: site_avail_topic(&cfg.home_assistant),
        payload: if online { "online" } else { "offline" }.into(),
        retain: true,
    }
}

fn val(v: Option<f64>) -> Option<String> {
    v.map(|x| format!("{x:.1}"))
}

/// Current states + per-entity availability. Unknown data => entity unavailable
/// (never a fabricated value).
pub fn states(cfg: &SiteConfig, snap: &EngineSnapshot, score: &Score) -> Vec<Publish> {
    let ha = &cfg.home_assistant;
    let mut out = Vec::new();
    let mut put = |oid: &str, v: Option<String>| {
        out.push(Publish {
            topic: avail_topic(ha, oid),
            payload: if v.is_some() { "online" } else { "offline" }.into(),
            retain: true,
        });
        if let Some(v) = v {
            out.push(Publish {
                topic: state_topic(ha, oid),
                payload: v,
                retain: true,
            });
        }
    };
    let dns: Vec<_> = snap
        .targets
        .iter()
        .filter(|t| t.kind == "dns" && t.stats.successes >= 3)
        .collect();
    let dns_p95 = dns
        .iter()
        .filter_map(|t| t.stats.p95_ms)
        .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |y| y.max(x))));
    put("network_dns_p95_latency", val(dns_p95));
    let wl: Vec<_> = snap
        .targets
        .iter()
        .filter(|t| t.vantage != "central" && t.kind == "icmp" && t.stats.successes >= 5)
        .collect();
    let wl_p95 = wl
        .iter()
        .filter_map(|t| t.stats.p95_ms)
        .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |y| y.max(x))));
    put("network_wireless_p95_latency", val(wl_p95));
    let (mut to, mut el) = (0u32, 0u32);
    for t in snap
        .targets
        .iter()
        .filter(|t| t.kind == "icmp" || t.kind == "udp_echo")
    {
        to += t.stats.timeouts;
        el += t.stats.eligible;
    }
    put(
        "network_packet_loss",
        (el >= 20).then(|| format!("{:.2}", f64::from(to) * 100.0 / f64::from(el))),
    );
    put("network_health_score", val(score.value));
    let congested = snap.incidents.iter().any(|i| {
        i.status != ho_logic::incidents::IncidentStatus::Resolved
            && matches!(
                i.hypothesis.kind,
                ho_logic::incidents::HypKind::WirelessPathDegraded
                    | ho_logic::incidents::HypKind::SharedLanCongestion
            )
    });
    put(
        "network_congested",
        Some(if congested { "ON" } else { "OFF" }.into()),
    );
    let dns_ok = if dns.is_empty() {
        None
    } else {
        Some(
            if dns.iter().all(|t| !t.health.is_bad()) {
                "ON"
            } else {
                "OFF"
            }
            .to_string(),
        )
    };
    put("dns_available", dns_ok);
    for n in &snap.nodes {
        let id = n.id.replace('-', "_");
        let online = match n.liveness {
            NodeLiveness::Online | NodeLiveness::Stale => Some("ON".to_string()),
            NodeLiveness::Missing => Some("OFF".to_string()),
            NodeLiveness::Unknown => None,
        };
        put(&format!("{id}_online"), online);
        let fresh = n.liveness == NodeLiveness::Online;
        put(
            &format!("{id}_wifi_rssi"),
            n.state.rssi_dbm.filter(|_| fresh).map(|r| r.to_string()),
        );
    }
    for a in cfg
        .assets
        .iter()
        .filter(|a| a.kind == ho_domain::AssetKind::AccessPoint)
    {
        let id = a.id.as_str().replace('-', "_");
        let down = snap.incidents.iter().any(|i| {
            i.status != ho_logic::incidents::IncidentStatus::Resolved
                && i.hypothesis.scope_assets.iter().any(|s| s == a.id.as_str())
                && matches!(
                    i.hypothesis.kind,
                    ho_logic::incidents::HypKind::ApUnavailable
                        | ho_logic::incidents::HypKind::ApRadioIssue
                )
        });
        let known = snap
            .targets
            .iter()
            .any(|t| t.asset.as_deref() == Some(a.id.as_str()))
            || down;
        put(
            &format!("{id}_available"),
            known.then(|| if down { "OFF" } else { "ON" }.to_string()),
        );
    }
    if cfg.privacy.location_enabled && cfg.privacy.publish_location_to_ha {
        for d in cfg.devices.iter().filter(|d| d.consent) {
            let id = d.id.as_str().replace('-', "_");
            let est = snap.locations.iter().find(|l| l.device_id == d.id.as_str());
            // Stale or unknown rooms are never published as current.
            let fresh = est.filter(|e| e.state == LocationState::Located);
            put(
                &format!("device_{id}_current_room"),
                fresh.and_then(|e| e.room_id.clone()),
            );
            put(
                &format!("device_{id}_location_confidence"),
                fresh.map(|e| format!("{:.0}", e.confidence * 100.0)),
            );
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use ho_logic::engine::Engine;

    fn cfg(loc: bool) -> SiteConfig {
        SiteConfig::from_yaml_str(&format!(
            r#"
schema_version: 1
site_id: home
nodes: [{{id: node-01}}]
assets: [{{id: ap-living, kind: access_point}}]
devices:
  - {{id: phone-1, kind: phone, name: Phone, consent: true, matcher: {{type: ibeacon, uuid: 01234567-89ab-cdef-0123-456789abcdef, major: 1, minor: 2}}}}
privacy: {{location_enabled: {loc}, publish_location_to_ha: {loc}}}
home_assistant: {{enabled: true}}
"#
        ))
        .unwrap()
    }

    #[test]
    fn discovery_has_stable_ids_and_availability() {
        let c = cfg(false);
        let d = discovery(&c);
        assert!(d.iter().all(|p| p.retain));
        let node = d
            .iter()
            .find(|p| p.topic.contains("node_01_online"))
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&node.payload).unwrap();
        assert_eq!(v["unique_id"], "observatory_home_node_01_online");
        assert_eq!(v["availability"].as_array().unwrap().len(), 2);
        assert!(
            !d.iter().any(|p| p.topic.contains("current_room")),
            "no location entities unless opted in"
        );
        let d2 = discovery(&cfg(true));
        assert!(d2
            .iter()
            .any(|p| p.topic.contains("device_phone_1_current_room")));
        assert_eq!(discovery(&c), discovery(&c), "deterministic");
    }

    #[test]
    fn unknown_states_are_unavailable_not_zero() {
        let c = cfg(true);
        let e = Engine::new(c.clone());
        let snap = e.snapshot();
        let score = ho_logic::recommend::score(&snap, 20);
        let s = states(&c, &snap, &score);
        let loss_av = s
            .iter()
            .find(|p| p.topic.ends_with("network_packet_loss/availability"))
            .unwrap();
        assert_eq!(loss_av.payload, "offline");
        assert!(!s
            .iter()
            .any(|p| p.topic.ends_with("network_packet_loss/state")));
        let room = s
            .iter()
            .find(|p| {
                p.topic
                    .ends_with("device_phone_1_current_room/availability")
            })
            .unwrap();
        assert_eq!(room.payload, "offline");
    }

    #[test]
    fn removal_clears_config_state_and_availability() {
        let r = removal(&cfg(true), &["device_phone_1_current_room".into()]);
        assert!(r.iter().all(|p| p.payload.is_empty() && p.retain));
        assert_eq!(r.len(), 4);
    }
}
