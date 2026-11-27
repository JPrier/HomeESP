//! Record payload types. Every record's wire layout is documented on its type and in
//! `docs/protocol.md`. Field order on the wire equals field order in the doc comment.

/// Record type discriminants (wire contract).
pub mod rtype {
    pub const WIFI_LINK: u8 = 1;
    pub const AP_SCAN: u8 = 2;
    pub const PROBE: u8 = 3;
    pub const LIFECYCLE: u8 = 4;
    pub const SYSTEM: u8 = 5;
    pub const BLE: u8 = 6;
    pub const SENSOR: u8 = 7;
    pub const CAPABILITIES: u8 = 8;
    pub const CONFIG_STATUS: u8 = 9;
    pub const NODE_STATUS: u8 = 10;
    pub const CONFIG_PARAMS: u8 = 16;
    pub const PROBE_TARGET: u8 = 17;
    pub const TRACKED_BSSID: u8 = 18;
    pub const ACK: u8 = 19;
}

/// Wi-Fi association status as reported by the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkStatus {
    Unknown = 0,
    Connected = 1,
    Connecting = 2,
    Disconnected = 3,
    NoApFound = 4,
    AuthFailed = 5,
}

impl LinkStatus {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Connected,
            2 => Self::Connecting,
            3 => Self::Disconnected,
            4 => Self::NoApFound,
            5 => Self::AuthFailed,
            _ => Self::Unknown,
        }
    }
}

/// `WifiLink` (type 1, 16 bytes):
/// `age_ms u32 | status u8 | rssi i8 | channel u8 | flags u8 | bssid [6] | assoc_gen u16`.
/// flags bit0 = rssi valid, bit1 = bssid valid. `age_ms` is the sample's age relative to
/// the frame's `sent_mono_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiLink {
    pub age_ms: u32,
    pub status: LinkStatus,
    pub rssi_dbm: Option<i8>,
    pub channel: u8,
    pub bssid: Option<[u8; 6]>,
    pub assoc_gen: u16,
}

/// Scan completeness flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScanCompleteness {
    Complete = 0,
    Partial = 1,
    Skipped = 2,
}

impl ScanCompleteness {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Complete),
            1 => Some(Self::Partial),
            2 => Some(Self::Skipped),
            _ => None,
        }
    }
}

/// One BSSID sample in an AP scan: `bssid [6] | channel u8 | rssi i8` (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApEntry {
    pub bssid: [u8; 6],
    pub channel: u8,
    pub rssi_dbm: i8,
}

/// AP entries either borrowed from a decoded frame or supplied for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApEntries<'a> {
    Raw(&'a [u8]),
    List(&'a [ApEntry]),
}

impl<'a> ApEntries<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Raw(b) => b.len() / 8,
            Self::List(l) => l.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = ApEntry> + 'a {
        let (raw, list): (&'a [u8], &'a [ApEntry]) = match *self {
            Self::Raw(b) => (b, &[]),
            Self::List(l) => (&[], l),
        };
        raw.chunks_exact(8)
            .map(|c| {
                let mut bssid = [0u8; 6];
                bssid.copy_from_slice(c.get(..6).unwrap_or(&[0; 6]));
                ApEntry {
                    bssid,
                    channel: c.get(6).copied().unwrap_or(0),
                    rssi_dbm: c.get(7).map(|v| *v as i8).unwrap_or(0),
                }
            })
            .chain(list.iter().copied())
    }
}

/// `ApScan` (type 2, 28 + 8n bytes):
/// `age_ms u32 | scan_id u16 | duration_ms u16 | completeness u8 | entry_count u8 |
///  channel_counts [14] u8 | reserved [4] | entries [entry_count * 8]`.
/// Only tracked (configured or own-network) BSSIDs are sent; channel counts are
/// non-identifying totals of all beacons heard per 2.4 GHz channel 1..=14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApScan<'a> {
    pub age_ms: u32,
    pub scan_id: u16,
    pub duration_ms: u16,
    pub completeness: ScanCompleteness,
    pub channel_counts: [u8; 14],
    pub entries: ApEntries<'a>,
}

/// Probe protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeKind {
    Icmp = 1,
    UdpEcho = 2,
    Dns = 3,
    Tcp = 4,
    Http = 5,
}

impl ProbeKind {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Icmp,
            2 => Self::UdpEcho,
            3 => Self::Dns,
            4 => Self::Tcp,
            5 => Self::Http,
            _ => return None,
        })
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::UdpEcho => "udp_echo",
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Http => "http",
        }
    }
}

/// Probe outcome classes (spec §8.3). A failed RTT is never encoded as zero: RTT is
/// only present when `outcome == Success`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeOutcome {
    Success = 0,
    Timeout = 1,
    RefusedUnreachable = 2,
    InvalidResponse = 3,
    ConfigError = 4,
    Unsupported = 5,
    Canceled = 6,
    SkippedDeferred = 7,
}

impl ProbeOutcome {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Success,
            1 => Self::Timeout,
            2 => Self::RefusedUnreachable,
            3 => Self::InvalidResponse,
            4 => Self::ConfigError,
            5 => Self::Unsupported,
            6 => Self::Canceled,
            7 => Self::SkippedDeferred,
            _ => return None,
        })
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::RefusedUnreachable => "refused_unreachable",
            Self::InvalidResponse => "invalid_response",
            Self::ConfigError => "config_error",
            Self::Unsupported => "unsupported",
            Self::Canceled => "canceled",
            Self::SkippedDeferred => "skipped_deferred",
        }
    }
    /// Whether this outcome counts as a sent-and-lost request in loss statistics.
    pub const fn counts_as_loss(self) -> bool {
        matches!(self, Self::Timeout)
    }
    /// Whether this outcome is an eligible attempt (denominator of loss).
    pub const fn is_eligible(self) -> bool {
        matches!(
            self,
            Self::Success | Self::Timeout | Self::RefusedUnreachable | Self::InvalidResponse
        )
    }
}

/// DNS answer validation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsAnswer {
    NotApplicable = 0,
    Match = 1,
    Mismatch = 2,
    ExpectedNxdomain = 3,
    UnexpectedNxdomain = 4,
    NoAnswer = 5,
    Servfail = 6,
    Refused = 7,
    Malformed = 8,
}

impl DnsAnswer {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::NotApplicable,
            1 => Self::Match,
            2 => Self::Mismatch,
            3 => Self::ExpectedNxdomain,
            4 => Self::UnexpectedNxdomain,
            5 => Self::NoAnswer,
            6 => Self::Servfail,
            7 => Self::Refused,
            8 => Self::Malformed,
            _ => return None,
        })
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "n/a",
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::ExpectedNxdomain => "expected_nxdomain",
            Self::UnexpectedNxdomain => "unexpected_nxdomain",
            Self::NoAnswer => "no_answer",
            Self::Servfail => "servfail",
            Self::Refused => "refused",
            Self::Malformed => "malformed",
        }
    }
    /// True when the DNS transaction produced the expected result.
    pub const fn is_good(self) -> bool {
        matches!(self, Self::Match | Self::ExpectedNxdomain)
    }
}

/// DNS details attached to a probe: `rcode u8 | answer u8 | transport u8 | qtype u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsDetail {
    pub rcode: u8,
    pub answer: DnsAnswer,
    /// 0 = UDP, 1 = TCP.
    pub transport: u8,
    pub qtype: u16,
}

/// `Probe` (type 3):
/// `age_ms u32 | target_len u8 | target | kind u8 | outcome u8 | flags u8 | dscp u8 |
///  rtt_us u32 | sched_late_ms u16 | error_code i16 | [dns: rcode u8 answer u8 transport u8 qtype u16]`.
/// flags bit0 = rtt valid, bit1 = overlapped a radio scan, bit2 = dns detail present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe<'a> {
    pub age_ms: u32,
    pub target_id: &'a str,
    pub kind: ProbeKind,
    pub outcome: ProbeOutcome,
    pub rtt_us: Option<u32>,
    pub scan_overlap: bool,
    pub dscp: u8,
    pub sched_late_ms: u16,
    pub error_code: i16,
    pub dns: Option<DnsDetail>,
}

/// Lifecycle event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleEvent {
    Boot = 1,
    WifiConnected = 2,
    WifiDisconnected = 3,
    GotIp = 4,
    MqttConnected = 5,
    MqttDisconnected = 6,
    ConfigApplied = 7,
    ConfigRejected = 8,
    BssidChanged = 9,
    DhcpChanged = 10,
    DataGap = 11,
}

impl LifecycleEvent {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Boot,
            2 => Self::WifiConnected,
            3 => Self::WifiDisconnected,
            4 => Self::GotIp,
            5 => Self::MqttConnected,
            6 => Self::MqttDisconnected,
            7 => Self::ConfigApplied,
            8 => Self::ConfigRejected,
            9 => Self::BssidChanged,
            10 => Self::DhcpChanged,
            11 => Self::DataGap,
            _ => return None,
        })
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::WifiConnected => "wifi_connected",
            Self::WifiDisconnected => "wifi_disconnected",
            Self::GotIp => "got_ip",
            Self::MqttConnected => "mqtt_connected",
            Self::MqttDisconnected => "mqtt_disconnected",
            Self::ConfigApplied => "config_applied",
            Self::ConfigRejected => "config_rejected",
            Self::BssidChanged => "bssid_changed",
            Self::DhcpChanged => "dhcp_changed",
            Self::DataGap => "data_gap",
        }
    }
}

/// `Lifecycle` (type 4, 24 bytes):
/// `age_ms u32 | event u8 | flags u8 | reason u16 | prior_bssid [6] | new_bssid [6] | duration_ms u32`.
/// `reason` is the raw SDK code (e.g. 802.11 disconnect reason). flags bit0 = prior
/// valid, bit1 = new valid, bit2 = duration valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifecycle {
    pub age_ms: u32,
    pub event: LifecycleEvent,
    pub reason: u16,
    pub prior_bssid: Option<[u8; 6]>,
    pub new_bssid: Option<[u8; 6]>,
    pub duration_ms: Option<u32>,
}

/// `System` (type 5):
/// `age_ms u32 | uptime_s u32 | heap_free u32 | heap_min u32 | heap_max_block u32 |
///  heap_frag_pct u8 | reset_reason u8 | queue_fill_pct u8 | reserved u8 |
///  drops_overflow u16 | drops_budget u16 | drops_expired u16 | missed_schedules u16 |
///  loop_lag_max_ms u16 | reconnects u16 | tx_bytes u32 | tx_frames u32 | fw_len u8 | fw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct System<'a> {
    pub age_ms: u32,
    pub uptime_s: u32,
    pub heap_free: u32,
    pub heap_min: u32,
    pub heap_max_block: u32,
    pub heap_frag_pct: u8,
    pub reset_reason: u8,
    pub queue_fill_pct: u8,
    pub drops_overflow: u16,
    pub drops_budget: u16,
    pub drops_expired: u16,
    pub missed_schedules: u16,
    pub loop_lag_max_ms: u16,
    pub reconnects: u16,
    pub tx_bytes: u32,
    pub tx_frames: u32,
    pub fw_version: &'a str,
}

/// `BleSummary` (type 6): `age_ms u32 | window_ms u16 | id_len u8 | device_id | count u16 |
///  rssi_min i8 | rssi_max i8 | rssi_sum i32 | last_seen_age_ms u16 | coverage_permille u16`.
/// `device_id` is the enrolled opaque id; nodes never send unmatched identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleSummary<'a> {
    pub age_ms: u32,
    pub window_ms: u16,
    pub device_id: &'a str,
    pub count: u16,
    pub rssi_min: i8,
    pub rssi_max: i8,
    pub rssi_sum: i32,
    pub last_seen_age_ms: u16,
    pub coverage_permille: u16,
}

/// `Sensor` (type 7): `age_ms u32 | id_len u8 | sensor_id | kind u8 | unit u8 |
///  value_milli i32 | quality u8 | calibration_rev u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sensor<'a> {
    pub age_ms: u32,
    pub sensor_id: &'a str,
    pub kind: u8,
    pub unit: u8,
    pub value_milli: i32,
    pub quality: u8,
    pub calibration_rev: u16,
}

/// Capability feature bits.
pub mod feature {
    pub const WIFI_STA: u32 = 1 << 0;
    pub const WIFI_5GHZ: u32 = 1 << 1;
    pub const BLE_OBSERVER: u32 = 1 << 2;
    pub const AP_SCAN_PASSIVE: u32 = 1 << 3;
    pub const PROBE_ICMP: u32 = 1 << 4;
    pub const PROBE_UDP_ECHO: u32 = 1 << 5;
    pub const PROBE_DNS: u32 = 1 << 6;
    pub const PROBE_TCP: u32 = 1 << 7;
    pub const OTA_AB: u32 = 1 << 8;
    pub const TLS: u32 = 1 << 9;
    pub const CSI: u32 = 1 << 10;
    pub const FLASH_ENCRYPTION: u32 = 1 << 11;
    pub const SENSOR_PORT: u32 = 1 << 12;
}

/// `Capabilities` (type 8): `chip_len u8 | chip | flash_kb u32 | ram_kb u16 |
///  features u32 | fw_len u8 | fw | profile_len u8 | profile | max_payload u16 |
///  max_probe_targets u8 | max_tracked_bssids u8 | max_ble_devices u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities<'a> {
    pub chip: &'a str,
    pub flash_kb: u32,
    pub ram_kb: u16,
    pub features: u32,
    pub fw_version: &'a str,
    pub profile: &'a str,
    pub max_payload: u16,
    pub max_probe_targets: u8,
    pub max_tracked_bssids: u8,
    pub max_ble_devices: u8,
}

/// Config application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigState {
    Applied = 0,
    Rejected = 1,
    Pending = 2,
}

impl ConfigState {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Applied),
            1 => Some(Self::Rejected),
            2 => Some(Self::Pending),
            _ => None,
        }
    }
}

/// Config rejection reasons.
pub mod reject {
    pub const NONE: u8 = 0;
    pub const STALE_REVISION: u8 = 1;
    pub const OUT_OF_RANGE: u8 = 2;
    pub const UNSUPPORTED_CAPABILITY: u8 = 3;
    pub const TOO_MANY_TARGETS: u8 = 4;
    pub const MALFORMED: u8 = 5;
    pub const STORAGE_ERROR: u8 = 6;
}

/// `ConfigStatus` (type 9, 10 bytes): `revision u64 | state u8 | reason u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigStatus {
    pub revision: u64,
    pub state: ConfigState,
    pub reason: u8,
}

/// `NodeStatus` (type 10, 6 bytes): `online u8 | reason u8 | uptime_s u32`.
/// `online = 0` with reason 1 is the broker-delivered last will.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStatus {
    pub online: bool,
    pub reason: u8,
    pub uptime_s: u32,
}

/// `ConfigParams` (type 16, 52 bytes): `revision u64 | report_ms u32 | wifi_link_ms u32 |
///  ap_scan_ms u32 | heartbeat_ms u32 | health_ms u32 | egress_bytes_per_sec u16 |
///  egress_burst_bytes u16 | max_payload u16 | offline_buffer_bytes u16 | flags u16 |
///  max_probe_inflight u8 | reserved u8 | scan_max_dwell_ms u16 | reserved [8]`.
/// flags bit0 = passive AP scan enabled, bit1 = BLE scan enabled, bit2 = CSI enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigParams {
    pub revision: u64,
    pub report_ms: u32,
    pub wifi_link_ms: u32,
    pub ap_scan_ms: u32,
    pub heartbeat_ms: u32,
    pub health_ms: u32,
    pub egress_bytes_per_sec: u16,
    pub egress_burst_bytes: u16,
    pub max_payload: u16,
    pub offline_buffer_bytes: u16,
    pub flags: u16,
    pub max_probe_inflight: u8,
    pub scan_max_dwell_ms: u16,
}

/// Config flag bits for [`ConfigParams::flags`].
pub mod cfgflag {
    pub const PASSIVE_SCAN: u16 = 1 << 0;
    pub const BLE_SCAN: u16 = 1 << 1;
    pub const CSI: u16 = 1 << 2;
}

/// Where a probe's destination comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddrSource {
    /// Use `ipv4` literally.
    Literal = 0,
    /// The node's DHCP gateway.
    Gateway = 1,
    /// The node's DHCP-assigned DNS resolver.
    AssignedResolver = 2,
    /// The MQTT broker / central server address.
    Server = 3,
}

impl AddrSource {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Literal),
            1 => Some(Self::Gateway),
            2 => Some(Self::AssignedResolver),
            3 => Some(Self::Server),
            _ => None,
        }
    }
}

/// DNS expectation for a DNS probe target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsExpect {
    AnyAnswer = 0,
    Nxdomain = 1,
    Ipv4 = 2,
}

impl DnsExpect {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::AnyAnswer),
            1 => Some(Self::Nxdomain),
            2 => Some(Self::Ipv4),
            _ => None,
        }
    }
}

/// `ProbeTarget` (type 17): `id_len u8 | id | kind u8 | addr_source u8 | ipv4 [4] |
///  port u16 | interval_ms u32 | timeout_ms u16 | dscp u8 | expect u8 | expect_ipv4 [4] |
///  qtype u16 | qname_len u8 | qname`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeTarget<'a> {
    pub id: &'a str,
    pub kind: ProbeKind,
    pub addr_source: AddrSource,
    pub ipv4: [u8; 4],
    pub port: u16,
    pub interval_ms: u32,
    pub timeout_ms: u16,
    pub dscp: u8,
    pub expect: DnsExpect,
    pub expect_ipv4: [u8; 4],
    pub qtype: u16,
    pub qname: &'a str,
}

/// `Ack` (type 19, 24 bytes): `boot_id [16] | sequence u64` — the events frame that is
/// now durably stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub boot_id: [u8; 16],
    pub sequence: u64,
}

/// A decoded or to-be-encoded record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record<'a> {
    WifiLink(WifiLink),
    ApScan(ApScan<'a>),
    Probe(Probe<'a>),
    Lifecycle(Lifecycle),
    System(System<'a>),
    Ble(BleSummary<'a>),
    Sensor(Sensor<'a>),
    Capabilities(Capabilities<'a>),
    ConfigStatus(ConfigStatus),
    NodeStatus(NodeStatus),
    ConfigParams(ConfigParams),
    ProbeTarget(ProbeTarget<'a>),
    TrackedBssid([u8; 6]),
    Ack(Ack),
    /// A record type this version does not understand; skipped by consumers.
    Unknown {
        rtype: u8,
        len: u16,
    },
}

impl Record<'_> {
    /// Wire type byte for this record.
    pub fn rtype(&self) -> u8 {
        match self {
            Self::WifiLink(_) => rtype::WIFI_LINK,
            Self::ApScan(_) => rtype::AP_SCAN,
            Self::Probe(_) => rtype::PROBE,
            Self::Lifecycle(_) => rtype::LIFECYCLE,
            Self::System(_) => rtype::SYSTEM,
            Self::Ble(_) => rtype::BLE,
            Self::Sensor(_) => rtype::SENSOR,
            Self::Capabilities(_) => rtype::CAPABILITIES,
            Self::ConfigStatus(_) => rtype::CONFIG_STATUS,
            Self::NodeStatus(_) => rtype::NODE_STATUS,
            Self::ConfigParams(_) => rtype::CONFIG_PARAMS,
            Self::ProbeTarget(_) => rtype::PROBE_TARGET,
            Self::TrackedBssid(_) => rtype::TRACKED_BSSID,
            Self::Ack(_) => rtype::ACK,
            Self::Unknown { rtype, .. } => *rtype,
        }
    }
}
