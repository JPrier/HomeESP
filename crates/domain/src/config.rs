//! Versioned site configuration (spec §6). Every unknown is configurable; nothing
//! site-specific is hardcoded. `validate()` returns every issue found (dry-run).

use crate::ids::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Broker usernames that must never be used as node ids (see deploy/mosquitto/acl).
pub const RESERVED_NODE_IDS: [&str; 2] = ["observatory-server", "homeassistant"];

/// Supported configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub schema_version: u32,
    pub site_id: SiteId,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub mqtt: MqttConfig,
    #[serde(default = "default_profiles")]
    pub profiles: BTreeMap<String, NodeProfile>,
    #[serde(default)]
    pub floors: Vec<Floor>,
    #[serde(default)]
    pub rooms: Vec<Room>,
    #[serde(default)]
    pub room_edges: Vec<RoomEdge>,
    #[serde(default)]
    pub nodes: Vec<NodeConf>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub radios: Vec<Radio>,
    #[serde(default)]
    pub probe_targets: Vec<ProbeTargetConf>,
    #[serde(default)]
    pub central_checks: Vec<CentralCheck>,
    #[serde(default)]
    pub devices: Vec<DeviceConf>,
    #[serde(default)]
    pub privacy: Privacy,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub retention: Retention,
    #[serde(default)]
    pub notifications: Notifications,
    #[serde(default)]
    pub home_assistant: HomeAssistant,
    #[serde(default)]
    pub integrations: Integrations,
    #[serde(default)]
    pub maintenance: Vec<MaintenanceWindow>,
    #[serde(default)]
    pub watchdog: Option<Watchdog>,
    #[serde(default)]
    pub experimental: Experimental,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// HTTP API/dashboard bind. Defaults to loopback; set a LAN address explicitly.
    pub bind: String,
    pub database_path: String,
    pub dashboard_dir: Option<String>,
    /// UDP echo responder bind (LAN only). `None` disables it.
    pub echo_bind: Option<String>,
    /// File with `operator=<token>` / `viewer=<token>` lines (never in this config).
    pub api_tokens_file: Option<String>,
    /// File with `node-id=<hex key>` lines for UDP echo authentication.
    pub echo_keys_file: Option<String>,
    /// Max accepted frames per node per second before shedding telemetry.
    pub max_frames_per_node_per_s: u32,
    /// Max frames buffered between MQTT intake and the writer.
    pub ingest_queue: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            database_path: "observatory.sqlite".into(),
            dashboard_dir: None,
            echo_bind: None,
            api_tokens_file: None,
            echo_keys_file: None,
            max_frames_per_node_per_s: 10,
            ingest_queue: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MqttConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// File containing only the password.
    pub password_file: Option<String>,
    pub tls_ca_file: Option<String>,
    /// Address nodes should use for "server" probes when it differs from `host`.
    pub keepalive_s: u16,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 1883,
            username: "observatory-server".into(),
            password_file: None,
            tls_ca_file: None,
            keepalive_s: 30,
        }
    }
}

/// Per-role/board collection profile pushed to nodes as desired config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NodeProfile {
    pub report_ms: u32,
    pub wifi_link_ms: u32,
    pub gateway_probe_ms: u32,
    pub server_probe_ms: u32,
    pub udp_probe_ms: u32,
    pub dns_probe_ms: u32,
    pub neighbor_scan_ms: u32,
    pub heartbeat_ms: u32,
    pub health_ms: u32,
    pub probe_timeout_ms: u16,
    pub max_publish_payload_bytes: u16,
    pub egress_bytes_per_sec: u16,
    pub egress_burst_bytes: u16,
    pub max_offline_buffer_bytes: u16,
    pub passive_scan_enabled: bool,
    pub scan_max_dwell_ms: u16,
    pub ble_enabled: bool,
    pub csi_enabled: bool,
    pub max_probe_inflight: u8,
}

impl Default for NodeProfile {
    fn default() -> Self {
        Self {
            report_ms: 2000,
            wifi_link_ms: 5000,
            gateway_probe_ms: 5000,
            server_probe_ms: 5000,
            udp_probe_ms: 10_000,
            dns_probe_ms: 30_000,
            neighbor_scan_ms: 120_000,
            heartbeat_ms: 10_000,
            health_ms: 60_000,
            probe_timeout_ms: 1000,
            max_publish_payload_bytes: 1024,
            egress_bytes_per_sec: 600,
            egress_burst_bytes: 1800,
            max_offline_buffer_bytes: 6144,
            passive_scan_enabled: true,
            scan_max_dwell_ms: 120,
            ble_enabled: false,
            csi_enabled: false,
            max_probe_inflight: 2,
        }
    }
}

fn default_profiles() -> BTreeMap<String, NodeProfile> {
    BTreeMap::from([("default".to_string(), NodeProfile::default())])
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub id: String,
    pub name: String,
    /// Meters per floor-plan unit.
    #[serde(default = "one")]
    pub scale_m: f64,
}

fn one() -> f64 {
    1.0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Room {
    pub id: RoomId,
    pub name: String,
    #[serde(default)]
    pub floor: Option<String>,
    /// Polygon vertices in floor units (meters after `scale_m`).
    #[serde(default)]
    pub polygon: Vec<[f64; 2]>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomEdge {
    pub from: RoomId,
    pub to: RoomId,
    #[serde(default = "yes")]
    pub bidirectional: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConf {
    pub id: NodeId,
    #[serde(default)]
    pub room: Option<RoomId>,
    #[serde(default = "default_profile_name")]
    pub profile: String,
    /// x, y, height in meters.
    #[serde(default)]
    pub position: Option<[f64; 3]>,
    #[serde(default)]
    pub board: Option<String>,
    /// Infrastructure asset this node normally associates through (for topology).
    #[serde(default)]
    pub expected_ap: Option<AssetId>,
}

fn default_profile_name() -> String {
    "default".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Wan,
    Router,
    DnsResolver,
    Switch,
    AccessPoint,
    Broker,
    Server,
    HomeAssistant,
    Service,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub id: AssetId,
    pub kind: AssetKind,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub critical: bool,
    #[serde(default)]
    pub address: Option<String>,
    /// Hard dependencies (all required).
    #[serde(default)]
    pub parents: Vec<AssetId>,
    /// Redundant alternatives: the asset is reachable while any one is healthy.
    #[serde(default)]
    pub redundant_parents: Vec<AssetId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Radio {
    /// BSSID "aa:bb:cc:dd:ee:ff" (infrastructure identifier).
    pub bssid: String,
    pub ap: AssetId,
    pub band: Band,
    #[serde(default)]
    pub channel: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Band {
    #[serde(rename = "2.4")]
    G24,
    #[serde(rename = "5")]
    G5,
    #[serde(rename = "6")]
    G6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKindConf {
    Icmp,
    UdpEcho,
    Dns,
    Tcp,
    Http,
}

/// Destination for a node probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrConf {
    Gateway,
    AssignedResolver,
    Server,
    Ipv4(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DnsExpectConf {
    AnyAnswer,
    Nxdomain,
    Ipv4 { address: String },
}

/// A probe executed by nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeTargetConf {
    pub id: TargetId,
    pub kind: ProbeKindConf,
    pub addr: AddrConf,
    /// Asset this probe evidences (for topology/incidents).
    #[serde(default)]
    pub asset: Option<AssetId>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub qname: Option<String>,
    #[serde(default)]
    pub qtype: Option<u16>,
    #[serde(default)]
    pub expect: Option<DnsExpectConf>,
    #[serde(default)]
    pub interval_ms: Option<u32>,
    #[serde(default)]
    pub timeout_ms: Option<u16>,
    #[serde(default)]
    pub critical: bool,
    /// Restrict to listed nodes; empty = all nodes.
    #[serde(default)]
    pub nodes: Vec<NodeId>,
}

/// A probe executed by the wired central server (the wired baseline vantage).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CentralCheck {
    pub id: TargetId,
    pub kind: ProbeKindConf,
    /// IPv4 literal or DNS name (allowlisted: only what is configured here is probed).
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub qname: Option<String>,
    #[serde(default)]
    pub qtype: Option<u16>,
    #[serde(default)]
    pub expect: Option<DnsExpectConf>,
    /// For HTTP checks: path on `host` (no redirects followed off-host).
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub https: bool,
    #[serde(default)]
    pub expect_status: Option<u16>,
    #[serde(default = "default_central_interval")]
    pub interval_ms: u32,
    #[serde(default = "default_central_timeout")]
    pub timeout_ms: u32,
    #[serde(default)]
    pub asset: Option<AssetId>,
    #[serde(default)]
    pub critical: bool,
    /// Pairs this check with a node probe id for wired-vs-wireless comparison.
    #[serde(default)]
    pub compare_with: Option<TargetId>,
}

fn default_central_interval() -> u32 {
    5000
}
fn default_central_timeout() -> u32 {
    1000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Phone,
    Wearable,
    PetTag,
    Item,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum MatcherConf {
    /// Stable opt-in advertisement (iBeacon). Values are not secrets but are protected.
    Ibeacon {
        uuid: String,
        major: u16,
        minor: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConf {
    pub id: DeviceId,
    pub kind: DeviceKind,
    pub name: String,
    pub matcher: MatcherConf,
    /// Explicit consent recorded by the operator. No collection without it.
    #[serde(default)]
    pub consent: bool,
    #[serde(default)]
    pub owner: Option<String>,
    /// Calibrated 1 m RSSI if known.
    #[serde(default)]
    pub tx_power_dbm: Option<i8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    pub location_enabled: bool,
    /// Only "none" is supported: unmatched BLE identifiers are never retained.
    pub unknown_ble_retention: String,
    pub location_history_days: u32,
    pub publish_location_to_ha: bool,
}

impl Default for Privacy {
    fn default() -> Self {
        Self {
            location_enabled: false,
            unknown_ble_retention: "none".into(),
            location_history_days: 30,
            publish_location_to_ha: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Thresholds {
    pub critical_consecutive_failures: u32,
    pub recovery_consecutive_successes: u32,
    pub recovery_stable_ms: i64,
    pub node_missing_ms: i64,
    pub loss_window_ms: i64,
    pub loss_min_samples: u32,
    pub loss_degraded_pct: f64,
    pub loss_critical_pct: f64,
    pub latency_p95_abs_ms: f64,
    pub latency_baseline_multiple: f64,
    pub latency_min_samples: u32,
    pub dns_failures_degraded: u32,
    pub correlation_window_ms: i64,
    pub recurrence_window_ms: i64,
    pub location: LocationThresholds,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            critical_consecutive_failures: 3,
            recovery_consecutive_successes: 3,
            recovery_stable_ms: 15_000,
            node_missing_ms: 30_000,
            loss_window_ms: 300_000,
            loss_min_samples: 20,
            loss_degraded_pct: 2.0,
            loss_critical_pct: 10.0,
            latency_p95_abs_ms: 100.0,
            latency_baseline_multiple: 2.0,
            latency_min_samples: 20,
            dns_failures_degraded: 3,
            correlation_window_ms: 60_000,
            recurrence_window_ms: 300_000,
            location: LocationThresholds::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LocationThresholds {
    pub window_ms: i64,
    pub lateness_ms: i64,
    pub stale_ms: i64,
    pub not_observed_ms: i64,
    pub min_confidence: f64,
    pub min_margin: f64,
    pub consecutive_windows: u32,
    pub ema_alpha: f64,
    pub sigma_db: f64,
}

impl Default for LocationThresholds {
    fn default() -> Self {
        Self {
            window_ms: 2000,
            lateness_ms: 5000,
            stale_ms: 10_000,
            not_observed_ms: 30_000,
            min_confidence: 0.70,
            min_margin: 0.15,
            consecutive_windows: 2,
            ema_alpha: 0.4,
            sigma_db: 6.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    pub raw_days: u32,
    pub location_days: u32,
    pub rollup_minute_days: u32,
    pub rollup_hour_days: u32,
    pub incident_days: u32,
    pub health_days: u32,
    pub max_db_mb: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            raw_days: 7,
            location_days: 30,
            rollup_minute_days: 90,
            rollup_hour_days: 365,
            incident_days: 365,
            health_days: 90,
            max_db_mb: 2048,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifierKind {
    Ntfy,
    Webhook,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifierConf {
    pub id: String,
    pub kind: NotifierKind,
    /// Must be https unless `allow_plain_http_lan` is set for a LAN endpoint.
    pub url: String,
    #[serde(default)]
    pub token_file: Option<String>,
    #[serde(default)]
    pub allow_plain_http_lan: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    5000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConf {
    pub notifier: String,
    pub min_severity: Severity,
    #[serde(default = "yes")]
    pub send_recovery: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Notifications {
    pub notifiers: Vec<NotifierConf>,
    pub routes: Vec<RouteConf>,
    /// Minimum ms between repeated messages for one incident.
    pub repeat_min_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HomeAssistant {
    pub enabled: bool,
    pub discovery_prefix: String,
    pub state_prefix: String,
    pub metrics_interval_ms: i64,
}

impl Default for HomeAssistant {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_prefix: "homeassistant".into(),
            state_prefix: "observatory/v1/home/ha".into(),
            metrics_interval_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Integrations {
    pub opnsense: Option<OpnsenseConf>,
    pub snmp: Vec<SnmpTargetConf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpnsenseConf {
    /// e.g. https://router.example.invalid
    pub base_url: String,
    pub key_file: String,
    pub secret_file: String,
    #[serde(default)]
    pub ca_file: Option<String>,
    #[serde(default = "default_opn_interval")]
    pub interval_ms: u32,
    #[serde(default)]
    pub asset: Option<AssetId>,
}

fn default_opn_interval() -> u32 {
    60_000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnmpTargetConf {
    pub asset: AssetId,
    pub host: String,
    #[serde(default = "default_snmp_port")]
    pub port: u16,
    /// v2c community file (legacy; requires `allow_legacy_v2c`).
    #[serde(default)]
    pub community_file: Option<String>,
    #[serde(default)]
    pub allow_legacy_v2c: bool,
    #[serde(default = "default_snmp_interval")]
    pub interval_ms: u32,
    /// ifIndex values to poll.
    #[serde(default)]
    pub interfaces: Vec<u32>,
}

fn default_snmp_port() -> u16 {
    161
}
fn default_snmp_interval() -> u32 {
    60_000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceWindow {
    pub asset: AssetId,
    pub start_ms: i64,
    pub end_ms: i64,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watchdog {
    /// HTTPS endpoint of an externally hosted heartbeat monitor.
    pub url: String,
    #[serde(default = "default_watchdog_interval")]
    pub interval_ms: u64,
}

fn default_watchdog_interval() -> u64 {
    60_000
}

/// Experimental features (spec D10): all disabled by default.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Experimental {
    pub csi: bool,
    pub coordinate_estimates: bool,
    pub capacity_tests: bool,
}

// ------------------------------------------------------------------ validation

/// One validation finding. `path` is a dotted location in the config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigIssue {
    pub path: String,
    pub message: String,
}

/// Parse error or semantic issues.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("{} validation issue(s): {}", .0.len(), .0.iter().map(|i| format!("{}: {}", i.path, i.message)).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<ConfigIssue>),
}

impl SiteConfig {
    /// Parse YAML and validate. Returns the config only if it has no issues.
    pub fn from_yaml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: SiteConfig =
            serde_yaml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let issues = cfg.validate();
        if issues.is_empty() {
            Ok(cfg)
        } else {
            Err(ConfigError::Invalid(issues))
        }
    }

    /// MQTT topic prefix for this site.
    pub fn topic_prefix(&self) -> String {
        format!("observatory/v1/{}", self.site_id)
    }

    /// Profile for a node (falls back to `default`).
    pub fn profile_for(&self, node: &NodeConf) -> NodeProfile {
        self.profiles
            .get(&node.profile)
            .or_else(|| self.profiles.get("default"))
            .cloned()
            .unwrap_or_default()
    }

    pub fn node(&self, id: &str) -> Option<&NodeConf> {
        self.nodes.iter().find(|n| n.id.as_str() == id)
    }

    pub fn asset(&self, id: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.id.as_str() == id)
    }

    /// Full semantic validation (dry run). Never panics.
    pub fn validate(&self) -> Vec<ConfigIssue> {
        let mut v = Issues::default();
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            v.push(
                "schema_version",
                format!(
                    "unsupported version {} (expected {CONFIG_SCHEMA_VERSION})",
                    self.schema_version
                ),
            );
        }
        self.validate_profiles(&mut v);
        self.validate_layout(&mut v);
        self.validate_assets(&mut v);
        self.validate_probes(&mut v);
        self.validate_devices(&mut v);
        self.validate_notifications(&mut v);
        self.validate_misc(&mut v);
        v.0
    }

    fn validate_profiles(&self, v: &mut Issues) {
        if !self.profiles.contains_key("default") {
            v.push("profiles", "a `default` profile is required");
        }
        for (name, p) in &self.profiles {
            let at = |f: &str| format!("profiles.{name}.{f}");
            range(v, &at("report_ms"), p.report_ms, 500, 60_000);
            range(v, &at("wifi_link_ms"), p.wifi_link_ms, 1000, 600_000);
            range(v, &at("heartbeat_ms"), p.heartbeat_ms, 1000, 120_000);
            range(v, &at("health_ms"), p.health_ms, 10_000, 600_000);
            for (f, val) in [
                ("gateway_probe_ms", p.gateway_probe_ms),
                ("server_probe_ms", p.server_probe_ms),
                ("udp_probe_ms", p.udp_probe_ms),
                ("dns_probe_ms", p.dns_probe_ms),
            ] {
                if val != 0 {
                    range(v, &at(f), val, 1000, 3_600_000);
                }
            }
            if p.neighbor_scan_ms != 0 {
                range(
                    v,
                    &at("neighbor_scan_ms"),
                    p.neighbor_scan_ms,
                    30_000,
                    3_600_000,
                );
            }
            range(
                v,
                &at("probe_timeout_ms"),
                u32::from(p.probe_timeout_ms),
                100,
                5000,
            );
            range(
                v,
                &at("egress_bytes_per_sec"),
                u32::from(p.egress_bytes_per_sec),
                100,
                4000,
            );
            if p.egress_burst_bytes < p.egress_bytes_per_sec || p.egress_burst_bytes > 8000 {
                v.push(
                    at("egress_burst_bytes"),
                    "must be >= egress_bytes_per_sec and <= 8000",
                );
            }
            range(
                v,
                &at("max_publish_payload_bytes"),
                u32::from(p.max_publish_payload_bytes),
                256,
                1024,
            );
            range(
                v,
                &at("max_offline_buffer_bytes"),
                u32::from(p.max_offline_buffer_bytes),
                0,
                16_384,
            );
            range(
                v,
                &at("scan_max_dwell_ms"),
                u32::from(p.scan_max_dwell_ms),
                50,
                300,
            );
            range(
                v,
                &at("max_probe_inflight"),
                u32::from(p.max_probe_inflight),
                1,
                2,
            );
            if p.csi_enabled && !self.experimental.csi {
                v.push(
                    at("csi_enabled"),
                    "CSI is experimental; enable experimental.csi explicitly",
                );
            }
        }
    }

    fn validate_layout(&self, v: &mut Issues) {
        let floors: BTreeSet<&str> = self.floors.iter().map(|f| f.id.as_str()).collect();
        dupes(v, "floors", self.floors.iter().map(|f| f.id.as_str()));
        for f in &self.floors {
            if !(f.scale_m.is_finite() && f.scale_m > 0.0) {
                v.push(
                    format!("floors.{}.scale_m", f.id),
                    "must be a positive finite number",
                );
            }
        }
        dupes(v, "rooms", self.rooms.iter().map(|r| r.id.as_str()));
        let rooms: BTreeSet<&str> = self.rooms.iter().map(|r| r.id.as_str()).collect();
        for r in &self.rooms {
            if let Some(f) = &r.floor {
                if !floors.is_empty() && !floors.contains(f.as_str()) {
                    v.push(
                        format!("rooms.{}.floor", r.id),
                        format!("unknown floor {f}"),
                    );
                }
            }
            if !r.polygon.is_empty() {
                if let Err(e) = validate_polygon(&r.polygon) {
                    v.push(format!("rooms.{}.polygon", r.id), e);
                }
            }
        }
        for (i, e) in self.room_edges.iter().enumerate() {
            for end in [&e.from, &e.to] {
                if !rooms.contains(end.as_str()) {
                    v.push(format!("room_edges[{i}]"), format!("unknown room {end}"));
                }
            }
            if e.from == e.to {
                v.push(format!("room_edges[{i}]"), "self-edge");
            }
        }
        dupes(v, "nodes", self.nodes.iter().map(|n| n.id.as_str()));
        for n in &self.nodes {
            if RESERVED_NODE_IDS.contains(&n.id.as_str()) {
                v.push(
                    format!("nodes.{}", n.id),
                    "reserved for a service account (broker ACL patterns)",
                );
            }
            if let Some(r) = &n.room {
                if !rooms.contains(r.as_str()) {
                    v.push(format!("nodes.{}.room", n.id), format!("unknown room {r}"));
                }
            }
            if !self.profiles.contains_key(&n.profile) {
                v.push(
                    format!("nodes.{}.profile", n.id),
                    format!("unknown profile {}", n.profile),
                );
            }
            if let Some(p) = n.position {
                if p.iter().any(|x| !x.is_finite()) {
                    v.push(format!("nodes.{}.position", n.id), "must be finite");
                }
            }
            if let Some(ap) = &n.expected_ap {
                if self.asset(ap.as_str()).is_none() {
                    v.push(
                        format!("nodes.{}.expected_ap", n.id),
                        format!("unknown asset {ap}"),
                    );
                }
            }
        }
    }

    fn validate_assets(&self, v: &mut Issues) {
        dupes(v, "assets", self.assets.iter().map(|a| a.id.as_str()));
        let ids: BTreeSet<&str> = self.assets.iter().map(|a| a.id.as_str()).collect();
        for a in &self.assets {
            for p in a.parents.iter().chain(&a.redundant_parents) {
                if !ids.contains(p.as_str()) {
                    v.push(
                        format!("assets.{}.parents", a.id),
                        format!("unknown asset {p}"),
                    );
                }
                if p == &a.id {
                    v.push(
                        format!("assets.{}.parents", a.id),
                        "asset depends on itself",
                    );
                }
            }
            if a.redundant_parents.len() == 1 {
                v.push(
                    format!("assets.{}.redundant_parents", a.id),
                    "a redundant group needs at least 2 alternatives",
                );
            }
        }
        if let Some(cycle) = find_cycle(&self.assets) {
            v.push(
                "assets",
                format!("hard dependency cycle: {}", cycle.join(" -> ")),
            );
        }
        dupes(v, "radios", self.radios.iter().map(|r| r.bssid.as_str()));
        for r in &self.radios {
            if parse_mac(&r.bssid).is_none() {
                v.push(
                    format!("radios.{}", r.bssid),
                    "bssid must be aa:bb:cc:dd:ee:ff",
                );
            }
            match self.asset(r.ap.as_str()) {
                None => v.push(
                    format!("radios.{}.ap", r.bssid),
                    format!("unknown asset {}", r.ap),
                ),
                Some(a) if a.kind != AssetKind::AccessPoint => v.push(
                    format!("radios.{}.ap", r.bssid),
                    "radio must belong to an access_point asset",
                ),
                Some(_) => {}
            }
        }
    }

    fn validate_probes(&self, v: &mut Issues) {
        dupes(
            v,
            "probe_targets/central_checks",
            self.probe_targets
                .iter()
                .map(|t| t.id.as_str())
                .chain(self.central_checks.iter().map(|c| c.id.as_str())),
        );
        if self.probe_targets.len() > 8 {
            v.push("probe_targets", "nodes support at most 8 probe targets");
        }
        for t in &self.probe_targets {
            let at = |f: &str| format!("probe_targets.{}.{f}", t.id);
            if let Some(i) = t.interval_ms {
                range(v, &at("interval_ms"), i, 1000, 3_600_000);
                if let Some(to) = t.timeout_ms {
                    if u32::from(to) >= i {
                        v.push(at("timeout_ms"), "must be < interval_ms");
                    }
                }
            }
            if let Some(to) = t.timeout_ms {
                range(v, &at("timeout_ms"), u32::from(to), 100, 5000);
            }
            if let AddrConf::Ipv4(a) = &t.addr {
                if a.parse::<std::net::Ipv4Addr>().is_err() {
                    v.push(at("addr"), "ipv4 must be a dotted-quad literal");
                }
            }
            match t.kind {
                ProbeKindConf::Dns => {
                    match &t.qname {
                        Some(q) if valid_qname(q) => {}
                        _ => v.push(at("qname"), "DNS probes need a valid qname (<= 63 chars)"),
                    }
                    if let Some(DnsExpectConf::Ipv4 { address }) = &t.expect {
                        if address.parse::<std::net::Ipv4Addr>().is_err() {
                            v.push(at("expect.address"), "must be an IPv4 literal");
                        }
                    }
                }
                ProbeKindConf::Tcp if t.port.is_none() => {
                    v.push(at("port"), "TCP probes need a port")
                }
                ProbeKindConf::Http => v.push(
                    at("kind"),
                    "HTTP probes are central-only (nodes report unsupported)",
                ),
                _ => {}
            }
            if let Some(a) = &t.asset {
                if self.asset(a.as_str()).is_none() {
                    v.push(at("asset"), format!("unknown asset {a}"));
                }
            }
            for n in &t.nodes {
                if self.node(n.as_str()).is_none() {
                    v.push(at("nodes"), format!("unknown node {n}"));
                }
            }
        }
        for c in &self.central_checks {
            let at = |f: &str| format!("central_checks.{}.{f}", c.id);
            range(v, &at("interval_ms"), c.interval_ms, 1000, 3_600_000);
            range(v, &at("timeout_ms"), c.timeout_ms, 100, 10_000);
            if c.timeout_ms >= c.interval_ms {
                v.push(at("timeout_ms"), "must be < interval_ms");
            }
            if c.host.is_empty() || c.host.len() > 253 || c.host.contains(['/', '@', ' ', '?', '#'])
            {
                v.push(at("host"), "must be a bare hostname or IP (no URL parts)");
            }
            match c.kind {
                ProbeKindConf::Dns if !c.qname.as_deref().is_some_and(valid_qname) => {
                    v.push(at("qname"), "DNS checks need a valid qname")
                }
                ProbeKindConf::Tcp if c.port.is_none() => {
                    v.push(at("port"), "TCP checks need a port")
                }
                ProbeKindConf::Http => {
                    if let Some(p) = &c.path {
                        if !p.starts_with('/') || p.contains("://") || p.len() > 256 {
                            v.push(
                                at("path"),
                                "must be an absolute path on the configured host",
                            );
                        }
                    }
                }
                ProbeKindConf::UdpEcho => v.push(at("kind"), "udp_echo is node-originated only"),
                _ => {}
            }
            if let Some(a) = &c.asset {
                if self.asset(a.as_str()).is_none() {
                    v.push(at("asset"), format!("unknown asset {a}"));
                }
            }
        }
    }

    fn validate_devices(&self, v: &mut Issues) {
        dupes(v, "devices", self.devices.iter().map(|d| d.id.as_str()));
        if self.devices.len() > 30 {
            v.push("devices", "at most 30 enrolled devices are supported");
        }
        for d in &self.devices {
            match &d.matcher {
                MatcherConf::Ibeacon { uuid, .. } => {
                    if !valid_uuid(uuid) {
                        v.push(
                            format!("devices.{}.matcher.uuid", d.id),
                            "must be a canonical 36-char UUID",
                        );
                    }
                }
            }
        }
        if self.privacy.unknown_ble_retention != "none" {
            v.push(
                "privacy.unknown_ble_retention",
                "only `none` is supported (unknown identifiers are never retained)",
            );
        }
        range(
            v,
            "privacy.location_history_days",
            self.privacy.location_history_days,
            1,
            90,
        );
    }

    fn validate_notifications(&self, v: &mut Issues) {
        dupes(
            v,
            "notifications.notifiers",
            self.notifications.notifiers.iter().map(|n| n.id.as_str()),
        );
        for n in &self.notifications.notifiers {
            let at = format!("notifications.notifiers.{}.url", n.id);
            if n.url.starts_with("https://") {
                continue;
            }
            if n.url.starts_with("http://") && n.allow_plain_http_lan {
                continue;
            }
            v.push(
                at,
                "must be https:// (or http:// with allow_plain_http_lan)",
            );
        }
        for (i, r) in self.notifications.routes.iter().enumerate() {
            if !self
                .notifications
                .notifiers
                .iter()
                .any(|n| n.id == r.notifier)
            {
                v.push(
                    format!("notifications.routes[{i}]"),
                    format!("unknown notifier {}", r.notifier),
                );
            }
        }
        if let Some(w) = &self.watchdog {
            if !w.url.starts_with("https://") {
                v.push("watchdog.url", "must be https://");
            }
            if w.interval_ms < 10_000 {
                v.push("watchdog.interval_ms", "must be >= 10000");
            }
        }
    }

    fn validate_misc(&self, v: &mut Issues) {
        let r = &self.retention;
        range(v, "retention.raw_days", r.raw_days, 1, 90);
        range(
            v,
            "retention.rollup_minute_days",
            r.rollup_minute_days,
            1,
            730,
        );
        range(v, "retention.rollup_hour_days", r.rollup_hour_days, 1, 3650);
        if r.max_db_mb < 64 {
            v.push("retention.max_db_mb", "must be >= 64");
        }
        for (i, m) in self.maintenance.iter().enumerate() {
            if m.end_ms <= m.start_ms {
                v.push(format!("maintenance[{i}]"), "end must be after start");
            }
            if self.asset(m.asset.as_str()).is_none() {
                v.push(
                    format!("maintenance[{i}].asset"),
                    format!("unknown asset {}", m.asset),
                );
            }
        }
        let t = &self.thresholds;
        if t.critical_consecutive_failures == 0 || t.recovery_consecutive_successes == 0 {
            v.push("thresholds", "consecutive counts must be >= 1");
        }
        if !(0.0..=100.0).contains(&t.loss_degraded_pct)
            || t.loss_critical_pct < t.loss_degraded_pct
        {
            v.push("thresholds.loss_*", "0 <= degraded <= critical <= 100");
        }
        let l = &t.location;
        if !(0.5..=1.0).contains(&l.min_confidence) || !(0.0..=0.5).contains(&l.min_margin) {
            v.push(
                "thresholds.location",
                "min_confidence in [0.5,1], min_margin in [0,0.5]",
            );
        }
        if !(0.0..=1.0).contains(&l.ema_alpha) || l.ema_alpha == 0.0 || l.sigma_db <= 0.0 {
            v.push("thresholds.location", "ema_alpha in (0,1], sigma_db > 0");
        }
        if let Some(o) = &self.integrations.opnsense {
            if !o.base_url.starts_with("https://") {
                v.push(
                    "integrations.opnsense.base_url",
                    "must be https:// (read-only API over TLS)",
                );
            }
        }
        for s in &self.integrations.snmp {
            if s.community_file.is_some() && !s.allow_legacy_v2c {
                v.push(
                    format!("integrations.snmp.{}", s.asset),
                    "SNMPv2c requires allow_legacy_v2c: true",
                );
            }
            if self.asset(s.asset.as_str()).is_none() {
                v.push(format!("integrations.snmp.{}", s.asset), "unknown asset");
            }
        }
    }
}

#[derive(Default)]
struct Issues(Vec<ConfigIssue>);

impl Issues {
    fn push(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.0.push(ConfigIssue {
            path: path.into(),
            message: msg.into(),
        });
    }
}

fn range(v: &mut Issues, path: &str, val: u32, lo: u32, hi: u32) {
    if val < lo || val > hi {
        v.push(path, format!("{val} out of range [{lo}, {hi}]"));
    }
}

fn dupes<'a>(v: &mut Issues, what: &str, ids: impl Iterator<Item = &'a str>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            v.push(what, format!("duplicate id {id}"));
        }
    }
}

/// Parse "aa:bb:cc:dd:ee:ff".
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (o, p) in out.iter_mut().zip(parts) {
        if p.len() != 2 {
            return None;
        }
        *o = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

/// Format a MAC as lowercase colon-hex.
pub fn format_mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// DNS qname rule shared with the wire protocol (<= 63 bytes total).
pub fn valid_qname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// Validate a simple polygon: >= 3 finite vertices, non-zero area, no self-intersections.
pub fn validate_polygon(p: &[[f64; 2]]) -> Result<(), String> {
    if p.len() < 3 {
        return Err("needs at least 3 vertices".into());
    }
    if p.len() > 256 {
        return Err("at most 256 vertices".into());
    }
    if p.iter().flatten().any(|x| !x.is_finite()) {
        return Err("vertices must be finite".into());
    }
    let n = p.len();
    let at = |i: usize| p.get(i % n).copied().unwrap_or([0.0, 0.0]);
    let area: f64 = (0..n)
        .map(|i| at(i)[0] * at(i + 1)[1] - at(i + 1)[0] * at(i)[1])
        .sum::<f64>()
        / 2.0;
    if area.abs() < 1e-9 {
        return Err("zero area".into());
    }
    for i in 0..n {
        for j in (i + 1)..n {
            // Skip adjacent edges (they share a vertex).
            if j == i + 1 || (i == 0 && j == n - 1) {
                continue;
            }
            if segments_intersect(at(i), at(i + 1), at(j), at(j + 1)) {
                return Err(format!("edges {i} and {j} intersect"));
            }
        }
    }
    Ok(())
}

fn segments_intersect(a: [f64; 2], b: [f64; 2], c: [f64; 2], d: [f64; 2]) -> bool {
    fn orient(p: [f64; 2], q: [f64; 2], r: [f64; 2]) -> f64 {
        (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])
    }
    let (o1, o2, o3, o4) = (
        orient(a, b, c),
        orient(a, b, d),
        orient(c, d, a),
        orient(c, d, b),
    );
    (o1 * o2 < 0.0) && (o3 * o4 < 0.0)
}

/// Find a cycle in hard (`parents`) dependencies. Redundant alternatives are modeled
/// separately and not part of the hard DAG.
pub fn find_cycle(assets: &[Asset]) -> Option<Vec<String>> {
    let edges: HashMap<&str, Vec<&str>> = assets
        .iter()
        .map(|a| {
            (
                a.id.as_str(),
                a.parents.iter().map(|p| p.as_str()).collect(),
            )
        })
        .collect();
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Temp,
        Done,
    }
    let mut marks: HashMap<&str, Mark> = HashMap::new();
    fn visit<'a>(
        n: &'a str,
        edges: &HashMap<&'a str, Vec<&'a str>>,
        marks: &mut HashMap<&'a str, Mark>,
        stack: &mut Vec<&'a str>,
    ) -> Option<Vec<String>> {
        match marks.get(n) {
            Some(Mark::Done) => return None,
            Some(Mark::Temp) => {
                let start = stack.iter().position(|s| *s == n).unwrap_or(0);
                let mut c: Vec<String> = stack.iter().skip(start).map(|s| s.to_string()).collect();
                c.push(n.to_string());
                return Some(c);
            }
            None => {}
        }
        marks.insert(n, Mark::Temp);
        stack.push(n);
        for p in edges.get(n).map(Vec::as_slice).unwrap_or(&[]) {
            if let Some(c) = visit(p, edges, marks, stack) {
                return Some(c);
            }
        }
        stack.pop();
        marks.insert(n, Mark::Done);
        None
    }
    let mut keys: Vec<&str> = edges.keys().copied().collect();
    keys.sort_unstable();
    for k in keys {
        let mut stack = Vec::new();
        if let Some(c) = visit(k, &edges, &mut marks, &mut stack) {
            return Some(c);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
schema_version: 1
site_id: home
rooms:
  - {id: living, name: Living room, polygon: [[0,0],[5,0],[5,4],[0,4]]}
  - {id: hall, name: Hallway}
room_edges:
  - {from: living, to: hall}
nodes:
  - {id: node-01, room: living}
  - {id: node-02, room: hall}
assets:
  - {id: gateway, kind: router, critical: true, address: 192.0.2.1}
  - {id: ap-living, kind: access_point, critical: true, parents: [gateway]}
radios:
  - {bssid: "02:00:00:00:00:01", ap: ap-living, band: "2.4"}
probe_targets:
  - {id: dns-local, kind: dns, addr: assigned_resolver, qname: router.home.arpa, asset: gateway}
"#;

    #[test]
    fn sample_config_is_valid() {
        let c = SiteConfig::from_yaml_str(SAMPLE).unwrap();
        assert_eq!(c.topic_prefix(), "observatory/v1/home");
        assert_eq!(c.profile_for(&c.nodes[0]).report_ms, 2000);
        assert!(
            !c.privacy.location_enabled,
            "location must be off by default"
        );
        assert!(!c.experimental.csi);
    }

    fn issues(yaml: &str) -> Vec<ConfigIssue> {
        let c: SiteConfig = serde_yaml::from_str(yaml).unwrap();
        c.validate()
    }

    #[test]
    fn detects_cycles_duplicates_bad_refs_and_polygons() {
        let y = SAMPLE.replace(
            "parents: [gateway]}",
            "parents: [gateway]}\n  - {id: gateway, kind: switch, parents: [ap-living]}",
        );
        let i = issues(&y);
        assert!(
            i.iter().any(|x| x.message.contains("duplicate id gateway")),
            "{i:?}"
        );
        let y = SAMPLE.replace(
            "- {id: gateway, kind: router, critical: true, address: 192.0.2.1}",
            "- {id: gateway, kind: router, critical: true, parents: [ap-living]}",
        );
        assert!(issues(&y).iter().any(|x| x.message.contains("cycle")));
        let y = SAMPLE.replace("room: hall}", "room: kitchen}");
        assert!(issues(&y)
            .iter()
            .any(|x| x.message.contains("unknown room kitchen")));
        let y = SAMPLE.replace("[[0,0],[5,0],[5,4],[0,4]]", "[[0,0],[5,4],[5,0],[0,4]]");
        assert!(issues(&y).iter().any(|x| x.path.contains("polygon")));
        let y = SAMPLE.replace("qname: router.home.arpa", "qname: bad..name");
        assert!(issues(&y).iter().any(|x| x.path.contains("qname")));
    }

    #[test]
    fn rejects_unsafe_limits_and_unknown_fields() {
        let y = format!("{SAMPLE}profiles:\n  default: {{egress_bytes_per_sec: 50000}}\n");
        assert!(issues(&y).iter().any(|x| x.path.contains("egress")));
        let y = format!("{SAMPLE}profiles:\n  default: {{csi_enabled: true}}\n");
        assert!(issues(&y)
            .iter()
            .any(|x| x.message.contains("experimental")));
        assert!(serde_yaml::from_str::<SiteConfig>(&format!("{SAMPLE}bogus_field: 1\n")).is_err());
        let y = format!(
            "{SAMPLE}notifications:\n  notifiers: [{{id: n, kind: ntfy, url: 'http://x'}}]\n"
        );
        assert!(issues(&y).iter().any(|x| x.message.contains("https")));
    }

    #[test]
    fn polygon_rules() {
        assert!(validate_polygon(&[[0.0, 0.0], [1.0, 0.0], [0.0, 1.0]]).is_ok());
        assert!(validate_polygon(&[[0.0, 0.0], [1.0, 0.0]]).is_err());
        assert!(validate_polygon(&[[0.0, 0.0], [1.0, 1.0], [2.0, 2.0]]).is_err());
        assert!(validate_polygon(&[[0.0, 0.0], [2.0, 2.0], [2.0, 0.0], [0.0, 2.0]]).is_err());
    }

    #[test]
    fn mac_roundtrip() {
        let m = parse_mac("02:aB:00:00:00:ff").unwrap();
        assert_eq!(format_mac(&m), "02:ab:00:00:00:ff");
        assert!(parse_mac("02:00:00:00:00").is_none());
    }
}
