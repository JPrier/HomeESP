// Home Observatory node firmware (ESP8266, Arduino core).
//
// Responsibilities (spec §4.1): observe, summarize, run small approved probes, report
// health, accept bounded configuration. It never classifies, localizes or alerts.
// All collection buffers are fixed-size and allocated statically at boot; the
// Arduino/lwIP/SDK stacks themselves do allocate and that is not claimed otherwise.
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <MQTT.h>
#include <WiFiUdp.h>
#include <string.h>

extern "C" {
#include <user_interface.h>
}

#include "ho_codec.h"
#include "ho_config.h"
#include "ho_core.h"
#include "ho_dns.h"
#include "ho_hmac.h"
#include "icmp.h"
#include "store.h"

#ifndef HO_FW_VERSION
#define HO_FW_VERSION "0.0.0-dev"
#endif
#ifndef HO_PROFILE
#define HO_PROFILE "esp8266-4m"
#endif

using namespace ho;
using node::icmp_begin;
using node::icmp_start;
using node::icmp_state;
using node::icmp_rtt_us;
using node::icmp_reset;
using node::IcmpState;

namespace {

// ------------------------------------------------------------------ capacities
constexpr size_t kTelemetryArena = 6144;
constexpr size_t kEventsArena = 2048;
constexpr int kMaxPendingProbes = 16;
constexpr int kMaxPendingLifecycle = 12;
constexpr uint32_t kTelemetryMaxAgeMs = 120000;  // drop stale normal samples
constexpr uint32_t kEventsMaxAgeMs = 600000;     // critical events retained 10 min
constexpr uint32_t kEventResendMs = 5000;
constexpr uint32_t kFeatures =
    feature::kWifiSta | feature::kApScan | feature::kIcmp | feature::kUdpEcho | feature::kDns | feature::kTcp;

// ------------------------------------------------------------------ state
node::Secrets g_sec;
node::NodeConfig g_cfg;
bool g_provisioned = false;

uint8_t g_boot_id[16];
uint64_t g_seq = 0;
uint32_t g_last_millis = 0;
uint64_t g_mono_hi = 0;

uint64_t mono_ms() {
  uint32_t m = millis();
  if (m < g_last_millis) g_mono_hi += (1ull << 32);
  g_last_millis = m;
  return g_mono_hi | m;
}

WiFiClient g_net;
MQTTClient g_mqtt(1100);
WiFiUDP g_udp_dns, g_udp_echo;
char g_topic_base[96];
char g_topic[128];

FrameQueue<kTelemetryArena, 24> g_tq;
FrameQueue<kEventsArena, 8> g_eq;
TokenBucket g_bucket;
uint8_t g_frame[kMaxFrame];
uint8_t g_scratch[kMaxFrame];

// counters
uint16_t g_drops_budget = 0, g_drops_pending = 0, g_reconnects = 0;
uint32_t g_tx_bytes = 0, g_tx_frames = 0;
uint16_t g_loop_lag_max = 0;
uint32_t g_last_loop = 0;

// Wi-Fi state
WiFiEventHandler g_h_conn, g_h_disc, g_h_ip;
uint16_t g_assoc_gen = 0;
uint8_t g_cur_bssid[6] = {0};
bool g_have_bssid = false;
uint32_t g_disc_at = 0;
uint16_t g_last_disc_reason = 0;
Backoff g_wifi_backoff(1000, 60000, 1);
Backoff g_mqtt_backoff(1000, 60000, 2);
uint32_t g_next_mqtt_try = 0;

LifecycleRec g_life[kMaxPendingLifecycle];
uint8_t g_life_n = 0;
uint16_t g_life_dropped = 0;

void push_life(Lifecycle ev, uint16_t reason, const uint8_t* prior, const uint8_t* next, bool has_dur, uint32_t dur) {
  if (g_life_n >= kMaxPendingLifecycle) { g_life_dropped++; return; }
  LifecycleRec& r = g_life[g_life_n++];
  memset(&r, 0, sizeof(r));
  r.age_ms = millis();  // absolute for now; converted to age at encode time
  r.event = ev;
  r.reason = reason;
  if (prior) { r.prior_valid = true; memcpy(r.prior, prior, 6); }
  if (next) { r.new_valid = true; memcpy(r.next, next, 6); }
  r.duration_valid = has_dur;
  r.duration_ms = dur;
}

// probes
struct Slot {
  bool active;
  uint8_t t;
  uint32_t start_ms, start_us, deadline_ms;
  uint16_t late;
  bool overlap;
  uint16_t dns_id;
  uint32_t echo_seq, nonce;
  IPAddress dst;
};
Periodic g_sched[node::kMaxTargets];
Slot g_slots[2];
ProbeRec g_probe_out[kMaxPendingProbes];
char g_probe_ids[kMaxPendingProbes][kMaxShortId + 1];
uint8_t g_probe_n = 0;
uint16_t g_icmp_seq = 0;
uint32_t g_echo_seq = 0;

// scan
volatile bool g_scan_running = false, g_scan_ready = false;
uint32_t g_scan_started = 0;
uint16_t g_scan_id = 0;
uint8_t g_scan_counts[14];
ApEntry g_scan_entries[kMaxApEntries];
uint8_t g_scan_n = 0;
uint16_t g_scan_duration = 0;
ScanCompleteness g_scan_state = ScanCompleteness::Complete;
uint32_t g_scan_done_at = 0;

Periodic g_p_report, g_p_link, g_p_scan, g_p_heartbeat, g_p_health;
bool g_have_link = false;
WifiLinkRec g_link;
bool g_send_health = false;
bool g_send_heartbeat = false;
bool g_need_caps = true;
bool g_need_cfg_report = true;
ConfigStatusRec g_cfg_status{0, ConfigState::Applied, reject::kNone};
uint32_t g_last_event_send = 0;
uint8_t g_event_tries = 0;

// ------------------------------------------------------------------ logging
void logf(const char* fmt, ...) {
  char b[160];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(b, sizeof b, fmt, ap);
  va_end(ap);
  Serial.print("LOG ");
  Serial.println(b);
}

// ------------------------------------------------------------------ frames
Header make_header(MsgKind k, uint8_t flags) {
  Header h;
  h.kind = k;
  h.flags = flags;
  h.node_id = g_sec.node_id;
  memcpy(h.boot_id, g_boot_id, 16);
  h.sequence = ++g_seq;
  h.sent_mono_ms = mono_ms();
  h.config_revision = g_cfg.params.revision;
  return h;
}

uint32_t age_of(uint32_t abs_ms, uint32_t now) { return now - abs_ms; }

const char* topic(const char* suffix) {
  snprintf(g_topic, sizeof g_topic, "%s/%s", g_topic_base, suffix);
  return g_topic;
}

bool publish_raw(const char* suffix, const uint8_t* d, size_t n, bool retained, int qos) {
  if (!g_mqtt.connected()) return false;
  bool ok = g_mqtt.publish(topic(suffix), (const char*)d, (int)n, retained, qos);
  if (ok) { g_tx_bytes += n; g_tx_frames++; }
  return ok;
}

void enqueue_telemetry(FrameWriter& w, uint64_t seq) {
  size_t n = w.finish();
  if (n && w.count()) g_tq.push(g_frame, (uint16_t)n, millis(), (uint8_t)MsgKind::Telemetry, seq);
}

// Build telemetry frames from everything pending. Fragments into multiple valid
// frames rather than ever exceeding max_payload.
void build_telemetry() {
  uint32_t now = millis();
  size_t limit = g_cfg.params.max_payload;
  FrameWriter w(g_frame, sizeof g_frame, limit);
  Header h = make_header(MsgKind::Telemetry, 0);
  w.begin(h);
  auto flush_and_restart = [&]() {
    enqueue_telemetry(w, h.sequence);
    h = make_header(MsgKind::Telemetry, 0);
    w.begin(h);
  };
  if (g_have_link) {
    WifiLinkRec l = g_link;
    l.age_ms = age_of(g_link.age_ms, now);
    if (w.push(l) != Err::Ok) { flush_and_restart(); w.push(l); }
    g_have_link = false;
  }
  for (uint8_t i = 0; i < g_probe_n; i++) {
    ProbeRec p = g_probe_out[i];
    p.target_id = g_probe_ids[i];
    p.age_ms = age_of(p.age_ms, now);
    if (w.push(p) != Err::Ok) { flush_and_restart(); if (w.push(p) != Err::Ok) g_drops_pending++; }
  }
  g_probe_n = 0;
  if (g_scan_ready) {
    ApScanRec s{age_of(g_scan_done_at, now), g_scan_id, g_scan_duration, g_scan_state, {0}, g_scan_entries, g_scan_n};
    memcpy(s.channel_counts, g_scan_counts, 14);
    if (w.push(s) != Err::Ok) { flush_and_restart(); w.push(s); }
    g_scan_ready = false;
  }
  if (g_send_health) {
    uint32_t heap = ESP.getFreeHeap();
    static uint32_t heap_min = 0xFFFFFFFF;
    if (heap < heap_min) heap_min = heap;
    uint32_t missed = 0;
    for (int i = 0; i < g_cfg.target_count; i++) missed += g_sched[i].missed();
    missed += g_p_report.missed() + g_p_link.missed();
    SystemRec s{0,
                (uint32_t)(mono_ms() / 1000),
                heap,
                heap_min,
                ESP.getMaxFreeBlockSize(),
                ESP.getHeapFragmentation(),
                (uint8_t)ESP.getResetInfoPtr()->reason,
                g_tq.fill_pct(),
                (uint16_t)(g_tq.dropped_overflow() + g_eq.dropped_overflow() + g_drops_pending),
                g_drops_budget,
                (uint16_t)(g_tq.dropped_expired() + g_eq.dropped_expired()),
                (uint16_t)(missed > 0xffff ? 0xffff : missed),
                g_loop_lag_max,
                g_reconnects,
                g_tx_bytes,
                g_tx_frames,
                HO_FW_VERSION};
    if (w.push(s) != Err::Ok) { flush_and_restart(); w.push(s); }
    g_send_health = false;
    g_loop_lag_max = 0;
  }
  if (g_send_heartbeat && w.count() == 0) {
    // Heartbeat piggybacks on any telemetry; only send a bare status if nothing else.
    w.push(NodeStatusRec{true, 0, (uint32_t)(mono_ms() / 1000)});
  }
  g_send_heartbeat = false;
  enqueue_telemetry(w, h.sequence);
}

void build_events() {
  if (g_life_n == 0 && g_life_dropped == 0) return;
  uint32_t now = millis();
  FrameWriter w(g_frame, sizeof g_frame, g_cfg.params.max_payload);
  Header h = make_header(MsgKind::Events, flag::kNeedsAck);
  w.begin(h);
  uint8_t used = 0;
  for (; used < g_life_n; used++) {
    LifecycleRec r = g_life[used];
    r.age_ms = age_of(r.age_ms, now);
    if (w.push(r) != Err::Ok) break;
  }
  if (g_life_dropped) {
    LifecycleRec gap{0, Lifecycle::DataGap, g_life_dropped, false, {0}, false, {0}, false, 0};
    if (w.push(gap) == Err::Ok) g_life_dropped = 0;
  }
  memmove(g_life, g_life + used, (g_life_n - used) * sizeof(LifecycleRec));
  g_life_n -= used;
  size_t n = w.finish();
  if (n && w.count()) g_eq.push(g_frame, (uint16_t)n, now, (uint8_t)MsgKind::Events, h.sequence);
}

void publish_retained_state() {
  // Capabilities (retained) and config status (retained) after (re)connect or change.
  if (g_need_caps) {
    FrameWriter w(g_scratch, sizeof g_scratch, kMaxFrame);
    Header h = make_header(MsgKind::Capabilities, 0);
    w.begin(h);
    CapabilitiesRec c{"ESP8266EX", ESP.getFlashChipRealSize() / 1024, 80, kFeatures, HO_FW_VERSION, HO_PROFILE,
                      (uint16_t)kMaxFrame, (uint8_t)node::kMaxTargets, (uint8_t)node::kMaxBssids, 0};
    w.push(c);
    size_t n = w.finish();
    if (publish_raw("capabilities", g_scratch, n, true, 1)) g_need_caps = false;
    FrameWriter s(g_scratch, sizeof g_scratch, kMaxFrame);
    Header hs = make_header(MsgKind::Status, 0);
    s.begin(hs);
    s.push(NodeStatusRec{true, 0, (uint32_t)(mono_ms() / 1000)});
    size_t m = s.finish();
    publish_raw("status", g_scratch, m, true, 1);
  }
  if (g_need_cfg_report) {
    FrameWriter w(g_scratch, sizeof g_scratch, kMaxFrame);
    Header h = make_header(MsgKind::ConfigReported, 0);
    w.begin(h);
    w.push(g_cfg_status);
    size_t n = w.finish();
    if (publish_raw("config/reported", g_scratch, n, true, 1)) g_need_cfg_report = false;
  }
}

// Drain queues under the token bucket: critical events first, then telemetry.
void drain() {
  if (!g_mqtt.connected()) return;
  uint32_t now = millis();
  g_eq.expire(now, kEventsMaxAgeMs);
  g_tq.expire(now, kTelemetryMaxAgeMs);
  const auto* e = g_eq.front();
  if (e && now - g_last_event_send >= kEventResendMs) {
    if (g_bucket.try_take(e->len, now)) {
      uint16_t n = g_eq.copy_front(g_scratch, sizeof g_scratch);
      publish_raw("events", g_scratch, n, false, 1);
      g_last_event_send = now;
      if (++g_event_tries > 120) { g_eq.pop(); g_event_tries = 0; }  // bounded retries
    }
  }
  for (int i = 0; i < 4; i++) {
    const auto* t = g_tq.front();
    if (!t) break;
    if (!g_bucket.try_take(t->len, now)) { break; }  // backpressure; data waits (and may expire)
    uint16_t n = g_tq.copy_front(g_scratch, sizeof g_scratch);
    if (!publish_raw("telemetry", g_scratch, n, false, 0)) break;
    g_tq.pop();
  }
}

// ------------------------------------------------------------------ config
struct DesiredSink : RecordSink {
  node::NodeConfig staged;
  bool got_params = false, overflow = false;
  void on_config_params(const ConfigParamsRec& p) override { staged.params = p; got_params = true; }
  void on_probe_target(const ProbeTargetRec& t) override {
    if (staged.target_count >= node::kMaxTargets) { overflow = true; return; }
    staged.targets[staged.target_count++] = t;
  }
  void on_tracked_bssid(const uint8_t* m) override {
    if (staged.bssid_count >= node::kMaxBssids) { overflow = true; return; }
    memcpy(staged.bssids[staged.bssid_count++], m, 6);
  }
};

void schedule_all();

void on_desired(const uint8_t* d, size_t n) {
  DecodedHeader h;
  static DesiredSink sink;
  memset(&sink.staged, 0, sizeof(sink.staged));
  sink.got_params = sink.overflow = false;
  DecodeErr de = decode_frame(d, n, &h, &sink);
  uint8_t reason = reject::kNone;
  if (de != DecodeErr::Ok || h.kind != MsgKind::ConfigDesired || strcmp(h.node_id, g_sec.node_id) != 0 || !sink.got_params)
    reason = reject::kMalformed;
  else if (sink.overflow)
    reason = reject::kTooMany;
  else if (sink.staged.params.revision == g_cfg.params.revision)
    return;  // already applied (retained redelivery)
  else
    reason = validate_config(sink.staged.params, g_cfg.params.revision, sink.staged.targets, sink.staged.target_count,
                             sink.staged.bssid_count,
                             ConfigLimits{kFeatures, node::kMaxTargets, node::kMaxBssids, (uint16_t)kTelemetryArena});
  if (reason == reject::kNone && !node::config_save(&sink.staged)) reason = reject::kStorage;
  if (reason != reject::kNone) {
    g_cfg_status = ConfigStatusRec{sink.got_params ? sink.staged.params.revision : 0, ConfigState::Rejected, reason};
    push_life(Lifecycle::ConfigRejected, reason, nullptr, nullptr, false, 0);
    logf("config rejected reason=%u", reason);
  } else {
    g_cfg = sink.staged;
    g_cfg_status = ConfigStatusRec{g_cfg.params.revision, ConfigState::Applied, reject::kNone};
    push_life(Lifecycle::ConfigApplied, 0, nullptr, nullptr, false, 0);
    logf("config applied rev=%u targets=%u", (unsigned)g_cfg.params.revision, g_cfg.target_count);
    schedule_all();
  }
  g_need_cfg_report = true;
}

void on_ack(const uint8_t* d, size_t n) {
  DecodedHeader h;
  struct AckSink : RecordSink {
    AckRec a{};
    bool got = false;
    void on_ack(const AckRec& r) override { a = r; got = true; }
  } s;
  if (decode_frame(d, n, &h, &s) != DecodeErr::Ok || !s.got) return;
  if (memcmp(s.a.boot_id, g_boot_id, 16) != 0) return;
  const auto* e = g_eq.front();
  if (e && e->seq == s.a.sequence) {
    g_eq.pop();
    g_event_tries = 0;
    g_last_event_send = 0;  // next pending event may go immediately
  }
}

void on_message(MQTTClient*, char t[], char bytes[], int len) {
  size_t bl = strlen(g_topic_base);
  if (strncmp(t, g_topic_base, bl) != 0 || len <= 0) return;
  const char* suffix = t + bl + 1;
  if (strcmp(suffix, "config/desired") == 0) on_desired((const uint8_t*)bytes, (size_t)len);
  else if (strcmp(suffix, "ack") == 0) on_ack((const uint8_t*)bytes, (size_t)len);
}

// ------------------------------------------------------------------ scheduling
uint32_t seed_for(const char* collector) { return fnv1a(collector, fnv1a(g_sec.node_id)); }

void schedule_all() {
  uint32_t now = millis();
  const ConfigParamsRec& p = g_cfg.params;
  g_p_report.configure(p.report_ms, seed_for("report"), now);
  g_p_link.configure(p.wifi_link_ms, seed_for("link"), now);
  g_p_heartbeat.configure(p.heartbeat_ms, seed_for("heartbeat"), now);
  g_p_health.configure(p.health_ms, seed_for("health"), now);
  if (p.ap_scan_ms && (p.flags & cfgflag::kPassiveScan)) g_p_scan.configure(p.ap_scan_ms, seed_for("scan"), now, 5000);
  else g_p_scan = Periodic();
  for (int i = 0; i < g_cfg.target_count; i++)
    g_sched[i].configure(g_cfg.targets[i].interval_ms, seed_for(g_cfg.targets[i].id), now, g_cfg.targets[i].interval_ms / 10);
  g_bucket.configure(p.egress_bytes_per_sec, p.egress_burst_bytes, now);
}

// ------------------------------------------------------------------ probes
bool resolve_dst(const ProbeTargetRec& t, IPAddress* out) {
  switch (t.addr_source) {
    case AddrSource::Literal: *out = IPAddress(t.ipv4[0], t.ipv4[1], t.ipv4[2], t.ipv4[3]); return true;
    case AddrSource::Gateway: *out = WiFi.gatewayIP(); return out->isSet();
    case AddrSource::AssignedResolver: *out = WiFi.dnsIP(0); return out->isSet();
    case AddrSource::Server: {
      if (out->fromString(g_sec.mqtt_host)) return true;
      // Resolved once per attempt by the core's DNS; bounded by the core's timeout.
      return WiFi.hostByName(g_sec.mqtt_host, *out, 1000) == 1;
    }
  }
  return false;
}

void finish_probe(Slot& s, Outcome o, uint32_t rtt_us, int16_t err, const DnsDetail* dns) {
  const ProbeTargetRec& t = g_cfg.targets[s.t];
  if (g_probe_n >= kMaxPendingProbes) { g_drops_pending++; s.active = false; return; }
  ProbeRec& r = g_probe_out[g_probe_n];
  strncpy(g_probe_ids[g_probe_n], t.id, kMaxShortId);
  g_probe_ids[g_probe_n][kMaxShortId] = 0;
  r.age_ms = s.start_ms;  // absolute; converted at encode
  r.target_id = g_probe_ids[g_probe_n];
  r.kind = t.kind;
  r.outcome = o;
  r.rtt_valid = o == Outcome::Success;
  r.rtt_us = r.rtt_valid ? rtt_us : 0;
  r.scan_overlap = s.overlap || g_scan_running;
  r.dscp = t.dscp;
  r.sched_late_ms = s.late;
  r.error_code = err;
  r.dns_present = dns != nullptr;
  if (dns) r.dns = *dns;
  g_probe_n++;
  s.active = false;
}

void start_probe(uint8_t ti, uint16_t late) {
  const ProbeTargetRec& t = g_cfg.targets[ti];
  Slot* s = nullptr;
  uint8_t inflight = 0;
  for (auto& x : g_slots) if (x.active) inflight++; else if (!s) s = &x;
  if (!s || inflight >= g_cfg.params.max_probe_inflight) {
    Slot tmp{true, ti, millis(), micros(), 0, late, false, 0, 0, 0, IPAddress()};
    finish_probe(tmp, Outcome::SkippedDeferred, 0, 1, nullptr);
    return;
  }
  *s = Slot{true, ti, millis(), 0, millis() + t.timeout_ms, late, g_scan_running, 0, 0, 0, IPAddress()};
  if (WiFi.status() != WL_CONNECTED) { finish_probe(*s, Outcome::SkippedDeferred, 0, 2, nullptr); return; }
  if (!resolve_dst(t, &s->dst)) { finish_probe(*s, Outcome::ConfigError, 0, 3, nullptr); return; }
  s->start_us = micros();
  switch (t.kind) {
    case ProbeKind::Icmp:
      for (auto& o : g_slots) if (&o != s && o.active && g_cfg.targets[o.t].kind == ProbeKind::Icmp) {
        finish_probe(*s, Outcome::SkippedDeferred, 0, 4, nullptr); return;  // one raw ICMP at a time
      }
      if (!icmp_start(s->dst, ++g_icmp_seq)) finish_probe(*s, Outcome::RefusedUnreachable, 0, 5, nullptr);
      else s->start_us = micros();
      return;
    case ProbeKind::Dns: {
      uint8_t q[96];
      s->dns_id = (uint16_t)RANDOM_REG32;
      size_t n = dns_build_query(q, sizeof q, s->dns_id, t.qname, t.qtype ? t.qtype : 1);
      if (!n) { finish_probe(*s, Outcome::ConfigError, 0, 6, nullptr); return; }
      while (g_udp_dns.parsePacket()) g_udp_dns.flush();
      g_udp_dns.beginPacket(s->dst, t.port ? t.port : 53);
      g_udp_dns.write(q, n);
      s->start_us = micros();
      if (!g_udp_dns.endPacket()) finish_probe(*s, Outcome::RefusedUnreachable, 0, 7, nullptr);
      return;
    }
    case ProbeKind::UdpEcho: {
      if (!g_sec.echo_key_len) { finish_probe(*s, Outcome::ConfigError, 0, 8, nullptr); return; }
      uint8_t pkt[64];
      s->echo_seq = ++g_echo_seq;
      s->nonce = RANDOM_REG32;
      size_t n = echo_build(pkt, sizeof pkt, false, g_sec.node_id, s->echo_seq, s->nonce, millis(), g_sec.echo_key,
                            g_sec.echo_key_len);
      while (g_udp_echo.parsePacket()) g_udp_echo.flush();
      g_udp_echo.beginPacket(s->dst, t.port ? t.port : g_sec.echo_port);
      g_udp_echo.write(pkt, n);
      s->start_us = micros();
      if (!g_udp_echo.endPacket()) finish_probe(*s, Outcome::RefusedUnreachable, 0, 9, nullptr);
      return;
    }
    case ProbeKind::Tcp: {
      WiFiClient c;
      c.setTimeout(t.timeout_ms);
      bool ok = c.connect(s->dst, t.port);
      uint32_t rtt = micros() - s->start_us;
      c.stop();
      if (ok) finish_probe(*s, Outcome::Success, rtt, 0, nullptr);
      else finish_probe(*s, (millis() >= s->deadline_ms) ? Outcome::Timeout : Outcome::RefusedUnreachable, 0, 10, nullptr);
      return;
    }
    case ProbeKind::Http:
      finish_probe(*s, Outcome::Unsupported, 0, 11, nullptr);
      return;
  }
}

void poll_probes() {
  uint32_t now = millis();
  for (auto& s : g_slots) {
    if (!s.active) continue;
    const ProbeTargetRec& t = g_cfg.targets[s.t];
    switch (t.kind) {
      case ProbeKind::Icmp: {
        IcmpState st = icmp_state();
        if (st == IcmpState::Replied) { uint32_t r = icmp_rtt_us(); icmp_reset(); finish_probe(s, Outcome::Success, r, 0, nullptr); continue; }
        break;
      }
      case ProbeKind::Dns: {
        int n = g_udp_dns.parsePacket();
        if (n > 0) {
          uint32_t rtt = micros() - s.start_us;
          uint8_t buf[512];
          int got = g_udp_dns.read(buf, sizeof buf);
          DnsResult r = dns_classify(buf, got > 0 ? (size_t)got : 0, s.dns_id, t.expect, t.expect_ipv4);
          if (r.error_code == -2) break;  // stale reply for an older query: keep waiting
          DnsDetail d{r.rcode, r.answer, 0, t.qtype ? t.qtype : (uint16_t)1};
          Outcome o = r.answer == DnsAnswer::Malformed ? Outcome::InvalidResponse : Outcome::Success;
          finish_probe(s, o, o == Outcome::Success ? rtt : 0, r.error_code, &d);
          continue;
        }
        break;
      }
      case ProbeKind::UdpEcho: {
        int n = g_udp_echo.parsePacket();
        if (n > 0) {
          uint32_t rtt = micros() - s.start_us;
          uint8_t buf[80];
          int got = g_udp_echo.read(buf, sizeof buf);
          if (got > 0 && echo_verify_response(buf, (size_t)got, g_sec.node_id, s.echo_seq, s.nonce, g_sec.echo_key, g_sec.echo_key_len)) {
            finish_probe(s, Outcome::Success, rtt, 0, nullptr);
            continue;
          }
        }
        break;
      }
      default:
        break;
    }
    if ((int32_t)(now - s.deadline_ms) >= 0) {
      if (t.kind == ProbeKind::Icmp) icmp_reset();
      DnsDetail d{0, DnsAnswer::NoAnswer, 0, t.qtype ? t.qtype : (uint16_t)1};
      finish_probe(s, Outcome::Timeout, 0, -1, t.kind == ProbeKind::Dns ? &d : nullptr);
    }
  }
}

// ------------------------------------------------------------------ AP scan
void on_scan_done(void* arg, STATUS status) {
  uint32_t now = millis();
  memset(g_scan_counts, 0, sizeof g_scan_counts);
  g_scan_n = 0;
  g_scan_state = status == OK ? ScanCompleteness::Complete : ScanCompleteness::Partial;
  const char* own = WiFi.SSID().c_str();
  for (bss_info* b = (bss_info*)arg; b && status == OK; b = STAILQ_NEXT(b, next)) {
    if (b->channel >= 1 && b->channel <= 14 && g_scan_counts[b->channel - 1] < 255) g_scan_counts[b->channel - 1]++;
    bool tracked = false;
    for (int i = 0; i < g_cfg.bssid_count; i++) if (memcmp(g_cfg.bssids[i], b->bssid, 6) == 0) tracked = true;
    // Own-network BSSIDs (same SSID as ours) are household infrastructure; other
    // networks contribute only to anonymous per-channel counts.
    if (!tracked && own && own[0] && b->ssid_len == strlen(own) && memcmp(b->ssid, own, b->ssid_len) == 0) tracked = true;
    if (tracked && g_scan_n < kMaxApEntries) {
      memcpy(g_scan_entries[g_scan_n].bssid, b->bssid, 6);
      g_scan_entries[g_scan_n].channel = b->channel;
      g_scan_entries[g_scan_n].rssi = b->rssi;
      g_scan_n++;
    }
  }
  g_scan_duration = (uint16_t)((now - g_scan_started) > 0xffff ? 0xffff : now - g_scan_started);
  g_scan_done_at = now;
  g_scan_running = false;
  g_scan_ready = true;
}

void maybe_scan(uint32_t now) {
  if (!g_p_scan.poll(now)) return;
  if (g_scan_running) return;
  bool busy = false;
  for (auto& s : g_slots) busy |= s.active;
  g_scan_id++;
  if (busy || WiFi.status() != WL_CONNECTED) {
    // Radio coordination: never scan over an in-flight probe; report the skip.
    g_scan_state = ScanCompleteness::Skipped;
    g_scan_n = 0;
    memset(g_scan_counts, 0, sizeof g_scan_counts);
    g_scan_duration = 0;
    g_scan_done_at = now;
    g_scan_ready = true;
    return;
  }
  static scan_config cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.show_hidden = 0;
  cfg.scan_type = WIFI_SCAN_TYPE_PASSIVE;
  cfg.scan_time.passive = g_cfg.params.scan_max_dwell_ms;
  g_scan_started = now;
  g_scan_running = true;
  if (!wifi_station_scan(&cfg, on_scan_done)) g_scan_running = false;
}

// ------------------------------------------------------------------ wifi / mqtt
void sample_link(uint32_t now) {
  g_link.age_ms = now;
  g_link.assoc_gen = g_assoc_gen;
  g_link.channel = (uint8_t)WiFi.channel();
  wl_status_t st = WiFi.status();
  g_link.status = st == WL_CONNECTED ? LinkStatus::Connected
                  : st == WL_NO_SSID_AVAIL ? LinkStatus::NoApFound
                  : st == WL_WRONG_PASSWORD ? LinkStatus::AuthFailed
                  : st == WL_DISCONNECTED ? LinkStatus::Disconnected
                  : LinkStatus::Connecting;
  g_link.rssi_valid = st == WL_CONNECTED;
  g_link.rssi = g_link.rssi_valid ? (int8_t)WiFi.RSSI() : 0;
  g_link.bssid_valid = st == WL_CONNECTED;
  if (g_link.bssid_valid) memcpy(g_link.bssid, WiFi.BSSID(), 6);
  g_have_link = true;
}

void wifi_begin() {
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);  // SDK reconnect; our backoff only governs MQTT
  WiFi.hostname(g_sec.node_id);
  g_h_conn = WiFi.onStationModeConnected([](const WiFiEventStationModeConnected& e) {
    g_assoc_gen++;
    bool changed = g_have_bssid && memcmp(g_cur_bssid, e.bssid, 6) != 0;
    uint32_t outage = g_disc_at ? millis() - g_disc_at : 0;
    push_life(changed ? Lifecycle::BssidChanged : Lifecycle::WifiConnected, e.channel, g_have_bssid ? g_cur_bssid : nullptr,
              e.bssid, g_disc_at != 0, outage);
    memcpy(g_cur_bssid, e.bssid, 6);
    g_have_bssid = true;
    g_disc_at = 0;
  });
  g_h_disc = WiFi.onStationModeDisconnected([](const WiFiEventStationModeDisconnected& e) {
    if (g_disc_at && g_last_disc_reason == e.reason) return;  // collapse retry storms into one event
    g_last_disc_reason = e.reason;
    if (!g_disc_at) g_disc_at = millis();
    push_life(Lifecycle::WifiDisconnected, e.reason, g_have_bssid ? g_cur_bssid : nullptr, nullptr, false, 0);
  });
  g_h_ip = WiFi.onStationModeGotIP([](const WiFiEventStationModeGotIP&) {
    push_life(Lifecycle::GotIp, 0, nullptr, nullptr, false, 0);
    g_last_disc_reason = 0;
  });
  WiFi.begin(g_sec.wifi_ssid, g_sec.wifi_psk);
}

void mqtt_tick(uint32_t now) {
  if (g_mqtt.connected()) { g_mqtt.loop(); return; }
  if (WiFi.status() != WL_CONNECTED || (int32_t)(now - g_next_mqtt_try) < 0) return;
  static bool was_connected = false;
  if (was_connected) { push_life(Lifecycle::MqttDisconnected, (uint16_t)g_mqtt.lastError(), nullptr, nullptr, false, 0); was_connected = false; }
  g_mqtt.begin(g_sec.mqtt_host, g_sec.mqtt_port, g_net);
  g_mqtt.setOptions(30, true, 2000);  // keepalive 30 s, clean session, 2 s command timeout
  g_mqtt.setWill(topic("status"), "offline", true, 1);
  char cid[48];
  snprintf(cid, sizeof cid, "ho-%s", g_sec.node_id);
  if (g_mqtt.connect(cid, g_sec.mqtt_user, g_sec.mqtt_pass)) {
    g_mqtt_backoff.reset();
    g_reconnects++;
    was_connected = true;
    g_mqtt.subscribe(topic("config/desired"), 1);
    g_mqtt.subscribe(topic("ack"), 1);
    g_need_caps = g_need_cfg_report = true;
    push_life(Lifecycle::MqttConnected, 0, nullptr, nullptr, false, 0);
    logf("mqtt connected");
  } else {
    uint32_t wait = g_mqtt_backoff.next();
    g_next_mqtt_try = now + wait;
    logf("mqtt connect failed err=%d rc=%d retry=%ums", (int)g_mqtt.lastError(), (int)g_mqtt.returnCode(), (unsigned)wait);
  }
}

// ------------------------------------------------------------------ provisioning
// Line protocol on the USB serial console (physical access required):
//   HO PING | HO SHOW | HO STATUS | HO SET <key> <value> | HO SAVE | HO REBOOT | HO FACTORY
// Secret values are never echoed back.
char g_line[200];
size_t g_line_n = 0;

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool set_str(char* dst, size_t cap, const char* v) {
  size_t n = strlen(v);
  if (n >= cap) return false;
  memcpy(dst, v, n + 1);
  return true;
}

void handle_line(char* line) {
  if (strncmp(line, "HO ", 3) != 0) return;
  char* cmd = line + 3;
  if (strcmp(cmd, "PING") == 0) {
    Serial.printf("HO OK PONG fw=%s chip=%08x provisioned=%d\n", HO_FW_VERSION, ESP.getChipId(), g_provisioned ? 1 : 0);
  } else if (strcmp(cmd, "SHOW") == 0) {
    Serial.printf("HO OK SHOW node_id=%s site=%s mqtt_host=%s mqtt_port=%u mqtt_user=%s wifi_ssid=%s psk=%s mqtt_pass=%s echo_key=%s echo_port=%u\n",
                  g_sec.node_id, g_sec.site, g_sec.mqtt_host, g_sec.mqtt_port, g_sec.mqtt_user, g_sec.wifi_ssid,
                  g_sec.wifi_psk[0] ? "<set>" : "<unset>", g_sec.mqtt_pass[0] ? "<set>" : "<unset>",
                  g_sec.echo_key_len ? "<set>" : "<unset>", g_sec.echo_port);
  } else if (strcmp(cmd, "STATUS") == 0) {
    Serial.printf("HO OK STATUS wifi=%d mqtt=%d rssi=%d heap=%u tq=%u eq=%u rev=%u seq=%u\n", WiFi.status(), g_mqtt.connected() ? 1 : 0,
                  WiFi.RSSI(), ESP.getFreeHeap(), (unsigned)g_tq.size(), (unsigned)g_eq.size(), (unsigned)g_cfg.params.revision,
                  (unsigned)g_seq);
  } else if (strncmp(cmd, "SET ", 4) == 0) {
    char* key = cmd + 4;
    char* val = strchr(key, ' ');
    if (!val) { Serial.println("HO ERR SET needs value"); return; }
    *val++ = 0;
    bool ok = false;
    if (!strcmp(key, "wifi_ssid")) ok = set_str(g_sec.wifi_ssid, sizeof g_sec.wifi_ssid, val);
    else if (!strcmp(key, "wifi_psk")) ok = set_str(g_sec.wifi_psk, sizeof g_sec.wifi_psk, val);
    else if (!strcmp(key, "node_id")) ok = valid_node_id(val) && set_str(g_sec.node_id, sizeof g_sec.node_id, val);
    else if (!strcmp(key, "site")) ok = valid_node_id(val) && set_str(g_sec.site, sizeof g_sec.site, val);
    else if (!strcmp(key, "mqtt_host")) ok = set_str(g_sec.mqtt_host, sizeof g_sec.mqtt_host, val);
    else if (!strcmp(key, "mqtt_port")) { long p = atol(val); ok = p > 0 && p < 65536; if (ok) g_sec.mqtt_port = (uint16_t)p; }
    else if (!strcmp(key, "mqtt_user")) ok = set_str(g_sec.mqtt_user, sizeof g_sec.mqtt_user, val);
    else if (!strcmp(key, "mqtt_pass")) ok = set_str(g_sec.mqtt_pass, sizeof g_sec.mqtt_pass, val);
    else if (!strcmp(key, "echo_port")) { long p = atol(val); ok = p > 0 && p < 65536; if (ok) g_sec.echo_port = (uint16_t)p; }
    else if (!strcmp(key, "echo_key")) {
      size_t n = strlen(val);
      ok = n >= 32 && n <= 64 && n % 2 == 0;
      for (size_t i = 0; ok && i < n / 2; i++) {
        int hi = hexval(val[2 * i]), lo = hexval(val[2 * i + 1]);
        ok = hi >= 0 && lo >= 0;
        if (ok) g_sec.echo_key[i] = (uint8_t)(hi * 16 + lo);
      }
      if (ok) g_sec.echo_key_len = (uint8_t)(n / 2);
    }
    memset(val, 0, strlen(val));  // scrub the line buffer copy of the value
    Serial.printf(ok ? "HO OK SET %s\n" : "HO ERR SET %s invalid\n", key);
  } else if (strcmp(cmd, "SAVE") == 0) {
    const char* missing = "";
    if (!node::secrets_complete(g_sec, &missing)) { Serial.printf("HO ERR SAVE missing=%s\n", missing); return; }
    Serial.println(node::secrets_save(&g_sec) ? "HO OK SAVED" : "HO ERR SAVE storage");
  } else if (strcmp(cmd, "REBOOT") == 0) {
    Serial.println("HO OK REBOOT");
    delay(100);
    ESP.restart();
  } else if (strcmp(cmd, "FACTORY") == 0) {
    node::store_factory_reset();
    Serial.println("HO OK FACTORY");
    delay(100);
    ESP.restart();
  } else {
    Serial.println("HO ERR unknown command");
  }
}

void serial_tick() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      g_line[g_line_n] = 0;
      handle_line(g_line);
      memset(g_line, 0, sizeof g_line);
      g_line_n = 0;
    } else if (g_line_n + 1 < sizeof g_line) {
      g_line[g_line_n++] = c;
    } else {
      g_line_n = 0;  // overlong line: discard
    }
  }
}

}  // namespace

// ------------------------------------------------------------------ entry points
void setup() {
  Serial.begin(115200);
  delay(50);
  for (int i = 0; i < 4; i++) { uint32_t r = RANDOM_REG32; memcpy(g_boot_id + 4 * i, &r, 4); }
  Serial.printf("\nLOG boot fw=%s profile=%s reset=%s\n", HO_FW_VERSION, HO_PROFILE, ESP.getResetReason().c_str());
  if (!node::store_begin()) logf("storage unavailable");
  node::secrets_load(&g_sec);
  const char* missing = "";
  g_provisioned = node::secrets_complete(g_sec, &missing);
  node::config_load(&g_cfg);
  g_cfg_status = ConfigStatusRec{g_cfg.params.revision, ConfigState::Applied, reject::kNone};
  push_life(Lifecycle::Boot, (uint16_t)ESP.getResetInfoPtr()->reason, nullptr, nullptr, false, 0);
  if (!g_provisioned) {
    logf("not provisioned (missing %s); waiting for serial provisioning", missing);
    return;
  }
  snprintf(g_topic_base, sizeof g_topic_base, "observatory/v1/%s/nodes/%s", g_sec.site, g_sec.node_id);
  g_mqtt.onMessageAdvanced(on_message);
  g_udp_dns.begin(0);
  g_udp_echo.begin(0);
  icmp_begin();
  schedule_all();
  wifi_begin();
  logf("node %s starting; config rev=%u", g_sec.node_id, (unsigned)g_cfg.params.revision);
}

void loop() {
  uint32_t now = millis();
  if (g_last_loop) {
    uint32_t lag = now - g_last_loop;
    if (lag > g_loop_lag_max) g_loop_lag_max = (uint16_t)(lag > 0xffff ? 0xffff : lag);
  }
  g_last_loop = now;
  serial_tick();
  if (!g_provisioned) { delay(10); return; }

  mqtt_tick(now);
  uint16_t late = 0;
  if (g_p_link.poll(now)) sample_link(now);
  if (g_p_heartbeat.poll(now)) g_send_heartbeat = true;
  if (g_p_health.poll(now)) g_send_health = true;
  maybe_scan(now);
  for (int i = 0; i < g_cfg.target_count; i++)
    if (g_sched[i].poll(now, &late)) start_probe((uint8_t)i, late);
  poll_probes();
  if (g_p_report.poll(now)) build_telemetry();
  build_events();
  if (g_mqtt.connected()) publish_retained_state();
  drain();
  delay(1);  // yield to the SDK; keeps the loop cooperative
}
