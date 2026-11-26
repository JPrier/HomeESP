#include "ho_codec.h"

#include <string.h>

namespace ho {

bool valid_node_id(const char* s) {
  if (!s) return false;
  size_t n = strlen(s);
  if (n == 0 || n > kMaxNodeId || s[0] == '-' || s[n - 1] == '-') return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  return true;
}

bool valid_short(const char* s, size_t max) {
  if (!s) return false;
  size_t n = strlen(s);
  if (n == 0 || n > max) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return false;
  }
  return true;
}

bool valid_qname(const char* s, size_t len) {
  if (len == 0 || len > kMaxQname) return false;
  size_t label = 0;
  for (size_t i = 0; i <= len; i++) {
    char c = i < len ? s[i] : '.';
    if (c == '.') {
      if (label == 0 || s[i - 1] == '-' || s[i - label] == '-') return false;
      label = 0;
      continue;
    }
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok || ++label > 63) return false;
  }
  return true;
}

// ------------------------------------------------------------------ writer

FrameWriter::FrameWriter(uint8_t* buf, size_t cap, size_t limit) : buf_(buf), cap_(cap) {
  limit_ = limit < kMaxFrame ? limit : kMaxFrame;
  if (limit_ > cap_) limit_ = cap_;
}

bool FrameWriter::put(const void* p, size_t n) {
  if (pos_ + n > limit_) return false;
  memcpy(buf_ + pos_, p, n);
  pos_ += n;
  return true;
}
bool FrameWriter::u16(uint16_t v) { uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)}; return put(b, 2); }
bool FrameWriter::u32(uint32_t v) {
  uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
  return put(b, 4);
}
bool FrameWriter::u64(uint64_t v) { return u32((uint32_t)v) && u32((uint32_t)(v >> 32)); }
bool FrameWriter::str(const char* s, size_t max) {
  if (!valid_short(s, max)) return false;
  size_t n = strlen(s);
  return u8((uint8_t)n) && put(s, n);
}

Err FrameWriter::begin(const Header& h) {
  pos_ = 0;
  count_ = 0;
  ok_ = false;
  if (!valid_node_id(h.node_id)) return Err::InvalidField;
  size_t n = strlen(h.node_id);
  bool ok = u8(kMagic0) && u8(kMagic1) && u16(kSchemaVersion) && u8((uint8_t)h.kind) && u8(h.flags) && u8((uint8_t)n) &&
            put(h.node_id, n) && put(h.boot_id, 16) && u64(h.sequence) && u64(h.sent_mono_ms) && u64(h.config_revision);
  if (!ok) return Err::BufferFull;
  count_pos_ = pos_;
  if (!u8(0)) return Err::BufferFull;
  ok_ = true;
  return Err::Ok;
}

Err FrameWriter::open(uint8_t type, size_t* start, size_t* len_pos) {
  if (!ok_) return Err::InvalidField;
  if (count_ == 255) return Err::TooManyRecords;
  *start = pos_;
  if (!u8(type)) return Err::BufferFull;
  *len_pos = pos_;
  if (!u16(0)) { pos_ = *start; return Err::BufferFull; }
  return Err::Ok;
}

Err FrameWriter::close(Err e, size_t start, size_t len_pos) {
  if (e != Err::Ok) { pos_ = start; return e; }
  size_t len = pos_ - len_pos - 2;
  buf_[len_pos] = (uint8_t)len;
  buf_[len_pos + 1] = (uint8_t)(len >> 8);
  count_++;
  return Err::Ok;
}

#define HO_OPEN(T)                          \
  size_t start_, lenpos_;                   \
  Err oe_ = open((T), &start_, &lenpos_);   \
  if (oe_ != Err::Ok) return oe_;
#define HO_CLOSE(expr) return close((expr) ? Err::Ok : Err::BufferFull, start_, lenpos_)

Err FrameWriter::push(const WifiLinkRec& r) {
  HO_OPEN(rtype::kWifiLink);
  static const uint8_t zero[6] = {0};
  uint8_t flags = (r.rssi_valid ? 1 : 0) | (r.bssid_valid ? 2 : 0);
  HO_CLOSE(u32(r.age_ms) && u8((uint8_t)r.status) && u8((uint8_t)(r.rssi_valid ? r.rssi : 0)) && u8(r.channel) && u8(flags) &&
           put(r.bssid_valid ? r.bssid : zero, 6) && u16(r.assoc_gen));
}

Err FrameWriter::push(const ApScanRec& r) {
  if (r.entry_count > kMaxApEntries) return Err::InvalidField;
  HO_OPEN(rtype::kApScan);
  static const uint8_t reserved[4] = {0};
  bool ok = u32(r.age_ms) && u16(r.scan_id) && u16(r.duration_ms) && u8((uint8_t)r.completeness) && u8(r.entry_count) &&
            put(r.channel_counts, 14) && put(reserved, 4);
  for (uint8_t i = 0; ok && i < r.entry_count; i++) {
    ok = put(r.entries[i].bssid, 6) && u8(r.entries[i].channel) && u8((uint8_t)r.entries[i].rssi);
  }
  HO_CLOSE(ok);
}

Err FrameWriter::push(const ProbeRec& r) {
  if (r.rtt_valid != (r.outcome == Outcome::Success)) return Err::InvalidField;
  if (!valid_short(r.target_id, kMaxShortId)) return Err::InvalidField;
  HO_OPEN(rtype::kProbe);
  uint8_t flags = (r.rtt_valid ? 1 : 0) | (r.scan_overlap ? 2 : 0) | (r.dns_present ? 4 : 0);
  bool ok = u32(r.age_ms) && str(r.target_id, kMaxShortId) && u8((uint8_t)r.kind) && u8((uint8_t)r.outcome) && u8(flags) &&
            u8(r.dscp) && u32(r.rtt_valid ? r.rtt_us : 0) && u16(r.sched_late_ms) && u16((uint16_t)r.error_code);
  if (ok && r.dns_present) ok = u8(r.dns.rcode) && u8((uint8_t)r.dns.answer) && u8(r.dns.transport) && u16(r.dns.qtype);
  HO_CLOSE(ok);
}

Err FrameWriter::push(const LifecycleRec& r) {
  HO_OPEN(rtype::kLifecycle);
  static const uint8_t zero[6] = {0};
  uint8_t flags = (r.prior_valid ? 1 : 0) | (r.new_valid ? 2 : 0) | (r.duration_valid ? 4 : 0);
  HO_CLOSE(u32(r.age_ms) && u8((uint8_t)r.event) && u8(flags) && u16(r.reason) && put(r.prior_valid ? r.prior : zero, 6) &&
           put(r.new_valid ? r.next : zero, 6) && u32(r.duration_valid ? r.duration_ms : 0));
}

Err FrameWriter::push(const SystemRec& r) {
  if (r.heap_frag_pct > 100 || r.queue_fill_pct > 100 || !valid_short(r.fw_version, kMaxLabel)) return Err::InvalidField;
  HO_OPEN(rtype::kSystem);
  HO_CLOSE(u32(r.age_ms) && u32(r.uptime_s) && u32(r.heap_free) && u32(r.heap_min) && u32(r.heap_max_block) && u8(r.heap_frag_pct) &&
           u8(r.reset_reason) && u8(r.queue_fill_pct) && u8(0) && u16(r.drops_overflow) && u16(r.drops_budget) &&
           u16(r.drops_expired) && u16(r.missed_schedules) && u16(r.loop_lag_max_ms) && u16(r.reconnects) && u32(r.tx_bytes) &&
           u32(r.tx_frames) && str(r.fw_version, kMaxLabel));
}

Err FrameWriter::push(const CapabilitiesRec& r) {
  if (!valid_short(r.chip, kMaxLabel) || !valid_short(r.fw_version, kMaxLabel) || !valid_short(r.profile, kMaxLabel)) return Err::InvalidField;
  HO_OPEN(rtype::kCapabilities);
  HO_CLOSE(str(r.chip, kMaxLabel) && u32(r.flash_kb) && u16(r.ram_kb) && u32(r.features) && str(r.fw_version, kMaxLabel) &&
           str(r.profile, kMaxLabel) && u16(r.max_payload) && u8(r.max_probe_targets) && u8(r.max_tracked_bssids) &&
           u8(r.max_ble_devices));
}

Err FrameWriter::push(const NodeStatusRec& r) {
  HO_OPEN(rtype::kNodeStatus);
  HO_CLOSE(u8(r.online ? 1 : 0) && u8(r.reason) && u32(r.uptime_s));
}

Err FrameWriter::push(const ConfigStatusRec& r) {
  HO_OPEN(rtype::kConfigStatus);
  HO_CLOSE(u64(r.revision) && u8((uint8_t)r.state) && u8(r.reason));
}

Err FrameWriter::push(const SensorRec& r) {
  if (!valid_short(r.sensor_id, kMaxShortId)) return Err::InvalidField;
  HO_OPEN(rtype::kSensor);
  HO_CLOSE(u32(r.age_ms) && str(r.sensor_id, kMaxShortId) && u8(r.kind) && u8(r.unit) && u32((uint32_t)r.value_milli) &&
           u8(r.quality) && u16(r.calibration_rev));
}

size_t FrameWriter::finish() {
  if (!ok_) return 0;
  buf_[count_pos_] = count_;
  return pos_;
}

// ------------------------------------------------------------------ reader

namespace {
struct Reader {
  const uint8_t* b;
  size_t len, pos;
  bool take(size_t n, const uint8_t** out) {
    if (n > len - pos) return false;
    *out = b + pos;
    pos += n;
    return true;
  }
  bool u8(uint8_t* v) { const uint8_t* p; if (!take(1, &p)) return false; *v = p[0]; return true; }
  bool u16(uint16_t* v) { const uint8_t* p; if (!take(2, &p)) return false; *v = (uint16_t)(p[0] | (p[1] << 8)); return true; }
  bool u32(uint32_t* v) {
    const uint8_t* p;
    if (!take(4, &p)) return false;
    *v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return true;
  }
  bool u64(uint64_t* v) { uint32_t lo, hi; if (!u32(&lo) || !u32(&hi)) return false; *v = ((uint64_t)hi << 32) | lo; return true; }
  bool bytes(uint8_t* dst, size_t n) { const uint8_t* p; if (!take(n, &p)) return false; memcpy(dst, p, n); return true; }
  // Length-prefixed string copied into dst (cap includes NUL); validated as short id.
  DecodeErr shortstr(char* dst, size_t max) {
    uint8_t n;
    const uint8_t* p;
    if (!u8(&n) || !take(n, &p)) return DecodeErr::RecordTooShort;
    if (n > max) return DecodeErr::BadString;
    memcpy(dst, p, n);
    dst[n] = 0;
    return valid_short(dst, max) ? DecodeErr::Ok : DecodeErr::BadString;
  }
};

// Decode one record into the sink (if non-null). Unknown types are accepted and skipped.
DecodeErr decode_record(uint8_t type, const uint8_t* p, size_t len, RecordSink* sink) {
  Reader r{p, len, 0};
  switch (type) {
    case rtype::kConfigParams: {
      ConfigParamsRec c;
      uint8_t reserved8[8], res;
      if (!(r.u64(&c.revision) && r.u32(&c.report_ms) && r.u32(&c.wifi_link_ms) && r.u32(&c.ap_scan_ms) && r.u32(&c.heartbeat_ms) &&
            r.u32(&c.health_ms) && r.u16(&c.egress_bytes_per_sec) && r.u16(&c.egress_burst_bytes) && r.u16(&c.max_payload) &&
            r.u16(&c.offline_buffer_bytes) && r.u16(&c.flags) && r.u8(&c.max_probe_inflight) && r.u8(&res) &&
            r.u16(&c.scan_max_dwell_ms) && r.bytes(reserved8, 8)))
        return DecodeErr::RecordTooShort;
      if (sink) sink->on_config_params(c);
      return DecodeErr::Ok;
    }
    case rtype::kProbeTarget: {
      ProbeTargetRec t;
      DecodeErr e = r.shortstr(t.id, kMaxShortId);
      if (e != DecodeErr::Ok) return e;
      uint8_t kind, src, expect, qlen;
      if (!(r.u8(&kind) && r.u8(&src) && r.bytes(t.ipv4, 4) && r.u16(&t.port) && r.u32(&t.interval_ms) && r.u16(&t.timeout_ms) &&
            r.u8(&t.dscp) && r.u8(&expect) && r.bytes(t.expect_ipv4, 4) && r.u16(&t.qtype) && r.u8(&qlen)))
        return DecodeErr::RecordTooShort;
      if (kind < 1 || kind > 5 || src > 3 || expect > 2) return DecodeErr::BadEnum;
      t.kind = (ProbeKind)kind;
      t.addr_source = (AddrSource)src;
      t.expect = (DnsExpect)expect;
      if (qlen > kMaxQname) return DecodeErr::BadString;
      if (!r.bytes((uint8_t*)t.qname, qlen)) return DecodeErr::RecordTooShort;
      t.qname[qlen] = 0;
      if (qlen > 0 && !valid_qname(t.qname, qlen)) return DecodeErr::BadString;
      if (sink) sink->on_probe_target(t);
      return DecodeErr::Ok;
    }
    case rtype::kTrackedBssid: {
      uint8_t m[6];
      if (!r.bytes(m, 6)) return DecodeErr::RecordTooShort;
      if (sink) sink->on_tracked_bssid(m);
      return DecodeErr::Ok;
    }
    case rtype::kAck: {
      AckRec a;
      if (!(r.bytes(a.boot_id, 16) && r.u64(&a.sequence))) return DecodeErr::RecordTooShort;
      if (sink) sink->on_ack(a);
      return DecodeErr::Ok;
    }
    default:
      return DecodeErr::Ok;  // unknown or node-originated record types: skipped
  }
}

DecodeErr walk(const uint8_t* buf, size_t len, DecodedHeader* h, RecordSink* sink, size_t records_at) {
  Reader r{buf, len, records_at};
  for (uint8_t i = 0; i < h->record_count; i++) {
    uint8_t type;
    uint16_t rlen;
    const uint8_t* p;
    if (!r.u8(&type) || !r.u16(&rlen) || !r.take(rlen, &p)) return DecodeErr::Truncated;
    DecodeErr e = decode_record(type, p, rlen, sink);
    if (e != DecodeErr::Ok) return e;
  }
  return r.pos == len ? DecodeErr::Ok : DecodeErr::Trailing;
}
}  // namespace

DecodeErr decode_frame(const uint8_t* buf, size_t len, DecodedHeader* h, RecordSink* sink) {
  if (len > kMaxFrame) return DecodeErr::TooLarge;
  Reader r{buf, len, 0};
  uint8_t m0, m1, kind, n;
  uint16_t schema;
  if (!r.u8(&m0) || !r.u8(&m1)) return DecodeErr::Truncated;
  if (m0 != kMagic0 || m1 != kMagic1) return DecodeErr::BadMagic;
  if (!r.u16(&schema)) return DecodeErr::Truncated;
  if (schema != kSchemaVersion) return DecodeErr::UnsupportedSchema;
  if (!r.u8(&kind) || !r.u8(&h->flags) || !r.u8(&n)) return DecodeErr::Truncated;
  if (!(kind >= 1 && kind <= 5) && kind != 16 && kind != 17) return DecodeErr::UnknownKind;
  h->kind = (MsgKind)kind;
  if (n > kMaxNodeId) return DecodeErr::BadNodeId;
  if (!r.bytes((uint8_t*)h->node_id, n)) return DecodeErr::Truncated;
  h->node_id[n] = 0;
  if (!valid_node_id(h->node_id)) return DecodeErr::BadNodeId;
  if (!(r.bytes(h->boot_id, 16) && r.u64(&h->sequence) && r.u64(&h->sent_mono_ms) && r.u64(&h->config_revision) &&
        r.u8(&h->record_count)))
    return DecodeErr::Truncated;
  size_t at = r.pos;
  DecodeErr e = walk(buf, len, h, nullptr, at);  // validate everything first
  if (e != DecodeErr::Ok) return e;
  if (sink) walk(buf, len, h, sink, at);
  return DecodeErr::Ok;
}

}  // namespace ho
