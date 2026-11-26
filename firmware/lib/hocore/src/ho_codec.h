// Home Observatory wire protocol v1 — C++ implementation for firmware.
// Mirrors crates/protocol (Rust). Byte-for-byte agreement is enforced by the shared
// golden vectors in tests/golden/protocol and firmware/test/host/test_codec.cpp.
// No heap allocation; all buffers are caller-owned.
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ho {

constexpr uint8_t kMagic0 = 'H';
constexpr uint8_t kMagic1 = 'O';
constexpr uint16_t kSchemaVersion = 1;
constexpr size_t kMaxFrame = 1024;
constexpr size_t kMaxNodeId = 32;
constexpr size_t kMaxShortId = 24;
constexpr size_t kMaxLabel = 24;
constexpr size_t kMaxQname = 63;
constexpr size_t kMaxApEntries = 32;

enum class MsgKind : uint8_t { Telemetry = 1, Events = 2, Status = 3, Capabilities = 4, ConfigReported = 5, ConfigDesired = 16, Ack = 17 };
namespace flag { constexpr uint8_t kNeedsAck = 1, kMoreFragments = 2, kReplayed = 4; }
namespace rtype {
constexpr uint8_t kWifiLink = 1, kApScan = 2, kProbe = 3, kLifecycle = 4, kSystem = 5, kBle = 6, kSensor = 7,
                  kCapabilities = 8, kConfigStatus = 9, kNodeStatus = 10, kConfigParams = 16, kProbeTarget = 17,
                  kTrackedBssid = 18, kAck = 19;
}
enum class LinkStatus : uint8_t { Unknown = 0, Connected = 1, Connecting = 2, Disconnected = 3, NoApFound = 4, AuthFailed = 5 };
enum class ProbeKind : uint8_t { Icmp = 1, UdpEcho = 2, Dns = 3, Tcp = 4, Http = 5 };
enum class Outcome : uint8_t { Success = 0, Timeout = 1, RefusedUnreachable = 2, InvalidResponse = 3, ConfigError = 4, Unsupported = 5, Canceled = 6, SkippedDeferred = 7 };
enum class DnsAnswer : uint8_t { NotApplicable = 0, Match = 1, Mismatch = 2, ExpectedNxdomain = 3, UnexpectedNxdomain = 4, NoAnswer = 5, Servfail = 6, Refused = 7, Malformed = 8 };
enum class Lifecycle : uint8_t { Boot = 1, WifiConnected = 2, WifiDisconnected = 3, GotIp = 4, MqttConnected = 5, MqttDisconnected = 6, ConfigApplied = 7, ConfigRejected = 8, BssidChanged = 9, DhcpChanged = 10, DataGap = 11 };
enum class ScanCompleteness : uint8_t { Complete = 0, Partial = 1, Skipped = 2 };
enum class ConfigState : uint8_t { Applied = 0, Rejected = 1, Pending = 2 };
enum class AddrSource : uint8_t { Literal = 0, Gateway = 1, AssignedResolver = 2, Server = 3 };
enum class DnsExpect : uint8_t { AnyAnswer = 0, Nxdomain = 1, Ipv4 = 2 };
namespace feature {
constexpr uint32_t kWifiSta = 1u << 0, kWifi5 = 1u << 1, kBle = 1u << 2, kApScan = 1u << 3, kIcmp = 1u << 4, kUdpEcho = 1u << 5,
                   kDns = 1u << 6, kTcp = 1u << 7, kOtaAb = 1u << 8, kTls = 1u << 9, kCsi = 1u << 10, kFlashEnc = 1u << 11, kSensor = 1u << 12;
}
namespace cfgflag { constexpr uint16_t kPassiveScan = 1, kBleScan = 2, kCsi = 4; }
namespace reject { constexpr uint8_t kNone = 0, kStale = 1, kRange = 2, kUnsupported = 3, kTooMany = 4, kMalformed = 5, kStorage = 6; }

struct Header {
  MsgKind kind;
  uint8_t flags;
  const char* node_id;  // NUL-terminated, validated
  uint8_t boot_id[16];
  uint64_t sequence;
  uint64_t sent_mono_ms;
  uint64_t config_revision;
};

struct WifiLinkRec { uint32_t age_ms; LinkStatus status; bool rssi_valid; int8_t rssi; uint8_t channel; bool bssid_valid; uint8_t bssid[6]; uint16_t assoc_gen; };
struct ApEntry { uint8_t bssid[6]; uint8_t channel; int8_t rssi; };
struct ApScanRec { uint32_t age_ms; uint16_t scan_id; uint16_t duration_ms; ScanCompleteness completeness; uint8_t channel_counts[14]; const ApEntry* entries; uint8_t entry_count; };
struct DnsDetail { uint8_t rcode; DnsAnswer answer; uint8_t transport; uint16_t qtype; };
struct ProbeRec { uint32_t age_ms; const char* target_id; ProbeKind kind; Outcome outcome; bool rtt_valid; uint32_t rtt_us; bool scan_overlap; uint8_t dscp; uint16_t sched_late_ms; int16_t error_code; bool dns_present; DnsDetail dns; };
struct LifecycleRec { uint32_t age_ms; Lifecycle event; uint16_t reason; bool prior_valid; uint8_t prior[6]; bool new_valid; uint8_t next[6]; bool duration_valid; uint32_t duration_ms; };
struct SystemRec { uint32_t age_ms, uptime_s, heap_free, heap_min, heap_max_block; uint8_t heap_frag_pct, reset_reason, queue_fill_pct; uint16_t drops_overflow, drops_budget, drops_expired, missed_schedules, loop_lag_max_ms, reconnects; uint32_t tx_bytes, tx_frames; const char* fw_version; };
struct CapabilitiesRec { const char* chip; uint32_t flash_kb; uint16_t ram_kb; uint32_t features; const char* fw_version; const char* profile; uint16_t max_payload; uint8_t max_probe_targets, max_tracked_bssids, max_ble_devices; };
struct NodeStatusRec { bool online; uint8_t reason; uint32_t uptime_s; };
struct ConfigStatusRec { uint64_t revision; ConfigState state; uint8_t reason; };
struct SensorRec { uint32_t age_ms; const char* sensor_id; uint8_t kind, unit; int32_t value_milli; uint8_t quality; uint16_t calibration_rev; };

// Decoded server->node records. Strings are copied into fixed arrays.
struct ConfigParamsRec { uint64_t revision; uint32_t report_ms, wifi_link_ms, ap_scan_ms, heartbeat_ms, health_ms; uint16_t egress_bytes_per_sec, egress_burst_bytes, max_payload, offline_buffer_bytes, flags; uint8_t max_probe_inflight; uint16_t scan_max_dwell_ms; };
struct ProbeTargetRec { char id[kMaxShortId + 1]; ProbeKind kind; AddrSource addr_source; uint8_t ipv4[4]; uint16_t port; uint32_t interval_ms; uint16_t timeout_ms; uint8_t dscp; DnsExpect expect; uint8_t expect_ipv4[4]; uint16_t qtype; char qname[kMaxQname + 1]; };
struct AckRec { uint8_t boot_id[16]; uint64_t sequence; };

bool valid_node_id(const char* s);
bool valid_short(const char* s, size_t max);
bool valid_qname(const char* s, size_t len);

enum class Err : uint8_t { Ok = 0, BufferFull, TooManyRecords, InvalidField };

// Frame builder. A failed push leaves the frame unchanged (callers flush and retry).
class FrameWriter {
 public:
  FrameWriter(uint8_t* buf, size_t cap, size_t limit);
  Err begin(const Header& h);
  Err push(const WifiLinkRec& r);
  Err push(const ApScanRec& r);
  Err push(const ProbeRec& r);
  Err push(const LifecycleRec& r);
  Err push(const SystemRec& r);
  Err push(const CapabilitiesRec& r);
  Err push(const NodeStatusRec& r);
  Err push(const ConfigStatusRec& r);
  Err push(const SensorRec& r);
  size_t finish();
  size_t len() const { return pos_; }
  uint8_t count() const { return count_; }

 private:
  bool put(const void* p, size_t n);
  bool u8(uint8_t v) { return put(&v, 1); }
  bool u16(uint16_t v);
  bool u32(uint32_t v);
  bool u64(uint64_t v);
  bool str(const char* s, size_t max);
  Err open(uint8_t type, size_t* start, size_t* len_pos);
  Err close(Err e, size_t start, size_t len_pos);
  uint8_t* buf_;
  size_t cap_, limit_, pos_ = 0, count_pos_ = 0;
  uint8_t count_ = 0;
  bool ok_ = false;
};

// Decoder for frames a node receives (ConfigDesired / Ack). Total and bounded.
enum class DecodeErr : uint8_t { Ok = 0, TooLarge, Truncated, BadMagic, UnsupportedSchema, UnknownKind, BadNodeId, BadString, BadEnum, RecordTooShort, Trailing, InvalidField };

struct DecodedHeader {
  MsgKind kind;
  uint8_t flags;
  char node_id[kMaxNodeId + 1];
  uint8_t boot_id[16];
  uint64_t sequence, sent_mono_ms, config_revision;
  uint8_t record_count;
};

// Visitor receives each understood record; unknown record types are skipped.
class RecordSink {
 public:
  virtual ~RecordSink() = default;
  virtual void on_config_params(const ConfigParamsRec&) {}
  virtual void on_probe_target(const ProbeTargetRec&) {}
  virtual void on_tracked_bssid(const uint8_t*) {}
  virtual void on_ack(const AckRec&) {}
};

// Validates the entire frame first; the sink is only invoked if everything is valid.
DecodeErr decode_frame(const uint8_t* buf, size_t len, DecodedHeader* out, RecordSink* sink);

}  // namespace ho
