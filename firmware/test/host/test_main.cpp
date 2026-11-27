// Host unit tests for the portable firmware core. Build & run:
//   firmware/test/host/run.sh   (g++ -std=c++17 -Wall -Wextra -Werror, optional sanitizers)
// No framework dependency: a tiny CHECK macro and a test registry.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "../../lib/hocore/src/ho_codec.h"
#include "../../lib/hocore/src/ho_config.h"
#include "../../lib/hocore/src/ho_core.h"
#include "../../lib/hocore/src/ho_dns.h"
#include "../../lib/hocore/src/ho_hmac.h"

static int g_failures = 0, g_checks = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    g_checks++;                                                        \
    if (!(cond)) {                                                     \
      g_failures++;                                                    \
      fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                  \
  } while (0)

struct TestCase { const char* name; void (*fn)(); };
static std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }
struct Reg { Reg(const char* n, void (*f)()) { registry().push_back({n, f}); } };
#define TEST(name) static void name(); static Reg reg_##name(#name, name); static void name()

static std::string golden_dir() {
  const char* d = getenv("HO_GOLDEN_DIR");
  return d ? d : "../../tests/golden/protocol";
}

static std::vector<uint8_t> read_hex(const std::string& name) {
  std::string path = golden_dir() + "/" + name + ".hex";
  FILE* f = fopen(path.c_str(), "rb");
  std::vector<uint8_t> out;
  if (!f) { fprintf(stderr, "  cannot open %s\n", path.c_str()); return out; }
  int hi = -1, c;
  while ((c = fgetc(f)) != EOF) {
    int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
    if (v < 0) continue;
    if (hi < 0) hi = v; else { out.push_back((uint8_t)(hi * 16 + v)); hi = -1; }
  }
  fclose(f);
  return out;
}

static const uint8_t BOOT[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t MAC_A[6] = {0x02, 0, 0, 0, 0, 0x01};
static const uint8_t MAC_B[6] = {0x02, 0, 0, 0, 0, 0x02};

static ho::Header hdr(ho::MsgKind k, uint8_t flags, uint64_t seq) {
  ho::Header h;
  h.kind = k;
  h.flags = flags;
  h.node_id = "node-01";
  memcpy(h.boot_id, BOOT, 16);
  h.sequence = seq;
  h.sent_mono_ms = 123456;
  h.config_revision = 7;
  return h;
}

// ---------------------------------------------------------------- codec golden

TEST(codec_telemetry_basic_matches_rust_golden) {
  uint8_t buf[1024];
  ho::FrameWriter w(buf, sizeof buf, 1024);
  CHECK(w.begin(hdr(ho::MsgKind::Telemetry, 0, 42)) == ho::Err::Ok);
  ho::WifiLinkRec wl{100, ho::LinkStatus::Connected, true, -61, 6, true, {0}, 3};
  memcpy(wl.bssid, MAC_A, 6);
  CHECK(w.push(wl) == ho::Err::Ok);
  ho::ProbeRec p1{50, "gw-icmp", ho::ProbeKind::Icmp, ho::Outcome::Success, true, 2345, false, 0, 3, 0, false, {}};
  CHECK(w.push(p1) == ho::Err::Ok);
  ho::ProbeRec p2{40, "dns-local", ho::ProbeKind::Dns, ho::Outcome::Timeout, false, 0, true, 0, 0, -1, true,
                  {0, ho::DnsAnswer::NoAnswer, 0, 1}};
  CHECK(w.push(p2) == ho::Err::Ok);
  ho::SystemRec s{0, 3600, 41000, 38500, 30000, 12, 6, 25, 1, 2, 3, 4, 15, 2, 100000, 500, "0.1.0"};
  CHECK(w.push(s) == ho::Err::Ok);
  size_t n = w.finish();
  std::vector<uint8_t> want = read_hex("telemetry_basic");
  CHECK(n == want.size());
  CHECK(n == want.size() && memcmp(buf, want.data(), n) == 0);
}

TEST(codec_events_lifecycle_matches_rust_golden) {
  uint8_t buf[256];
  ho::FrameWriter w(buf, sizeof buf, 1024);
  CHECK(w.begin(hdr(ho::MsgKind::Events, ho::flag::kNeedsAck, 43)) == ho::Err::Ok);
  ho::LifecycleRec a{5000, ho::Lifecycle::WifiDisconnected, 201, true, {0}, false, {0}, true, 5000};
  memcpy(a.prior, MAC_A, 6);
  CHECK(w.push(a) == ho::Err::Ok);
  ho::LifecycleRec b{9000, ho::Lifecycle::Boot, 6, false, {0}, false, {0}, false, 0};
  CHECK(w.push(b) == ho::Err::Ok);
  size_t n = w.finish();
  std::vector<uint8_t> want = read_hex("events_lifecycle");
  CHECK(n == want.size() && memcmp(buf, want.data(), n) == 0);
}

TEST(codec_ap_scan_matches_rust_golden) {
  uint8_t buf[256];
  ho::FrameWriter w(buf, sizeof buf, 1024);
  CHECK(w.begin(hdr(ho::MsgKind::Telemetry, 0, 44)) == ho::Err::Ok);
  ho::ApEntry e[2];
  memcpy(e[0].bssid, MAC_A, 6); e[0].channel = 1; e[0].rssi = -58;
  memcpy(e[1].bssid, MAC_B, 6); e[1].channel = 6; e[1].rssi = -77;
  ho::ApScanRec r{10, 5, 1800, ho::ScanCompleteness::Complete, {0}, e, 2};
  r.channel_counts[0] = 9; r.channel_counts[5] = 4; r.channel_counts[10] = 7;
  CHECK(w.push(r) == ho::Err::Ok);
  size_t n = w.finish();
  std::vector<uint8_t> want = read_hex("ap_scan");
  CHECK(n == want.size() && memcmp(buf, want.data(), n) == 0);
}

TEST(codec_capabilities_matches_rust_golden) {
  uint8_t buf[256];
  ho::FrameWriter w(buf, sizeof buf, 1024);
  CHECK(w.begin(hdr(ho::MsgKind::Capabilities, 0, 1)) == ho::Err::Ok);
  using namespace ho::feature;
  ho::CapabilitiesRec c{"ESP8266EX", 4096, 80, kWifiSta | kApScan | kIcmp | kUdpEcho | kDns | kTcp, "0.1.0", "esp8266-4m", 1024, 8, 16, 0};
  CHECK(w.push(c) == ho::Err::Ok);
  CHECK(w.push(ho::NodeStatusRec{true, 0, 12}) == ho::Err::Ok);
  size_t n = w.finish();
  std::vector<uint8_t> want = read_hex("capabilities");
  CHECK(n == want.size() && memcmp(buf, want.data(), n) == 0);
}

struct CaptureSink : ho::RecordSink {
  int params = 0, targets = 0, bssids = 0, acks = 0;
  ho::ConfigParamsRec p{};
  ho::ProbeTargetRec t[4]{};
  uint8_t bssid[6]{};
  ho::AckRec ack{};
  void on_config_params(const ho::ConfigParamsRec& r) override { p = r; params++; }
  void on_probe_target(const ho::ProbeTargetRec& r) override { if (targets < 4) t[targets] = r; targets++; }
  void on_tracked_bssid(const uint8_t* m) override { memcpy(bssid, m, 6); bssids++; }
  void on_ack(const ho::AckRec& a) override { ack = a; acks++; }
};

TEST(codec_decodes_rust_config_desired) {
  std::vector<uint8_t> f = read_hex("config_desired");
  ho::DecodedHeader h;
  CaptureSink s;
  CHECK(ho::decode_frame(f.data(), f.size(), &h, &s) == ho::DecodeErr::Ok);
  CHECK(h.kind == ho::MsgKind::ConfigDesired);
  CHECK(strcmp(h.node_id, "node-01") == 0);
  CHECK(s.params == 1 && s.p.revision == 7 && s.p.report_ms == 2000 && s.p.ap_scan_ms == 120000);
  CHECK(s.p.egress_bytes_per_sec == 600 && s.p.egress_burst_bytes == 1800 && s.p.max_probe_inflight == 2);
  CHECK(s.p.scan_max_dwell_ms == 120 && s.p.flags == ho::cfgflag::kPassiveScan);
  CHECK(s.targets == 2);
  CHECK(strcmp(s.t[0].id, "gw-icmp") == 0 && s.t[0].kind == ho::ProbeKind::Icmp && s.t[0].addr_source == ho::AddrSource::Gateway);
  CHECK(strcmp(s.t[1].qname, "router.home.arpa") == 0 && s.t[1].expect == ho::DnsExpect::Ipv4 && s.t[1].expect_ipv4[0] == 192);
  CHECK(s.bssids == 1 && memcmp(s.bssid, MAC_B, 6) == 0);
}

TEST(codec_decodes_rust_ack) {
  std::vector<uint8_t> f = read_hex("ack");
  ho::DecodedHeader h;
  CaptureSink s;
  CHECK(ho::decode_frame(f.data(), f.size(), &h, &s) == ho::DecodeErr::Ok);
  CHECK(s.acks == 1 && s.ack.sequence == 43 && memcmp(s.ack.boot_id, BOOT, 16) == 0);
}

TEST(codec_decoder_rejects_every_truncation_and_mutation_safely) {
  std::vector<uint8_t> f = read_hex("config_desired");
  ho::DecodedHeader h;
  CaptureSink s;
  for (size_t n = 0; n < f.size(); n++) CHECK(ho::decode_frame(f.data(), n, &h, &s) != ho::DecodeErr::Ok);
  CHECK(s.params == 0);  // sink never invoked on invalid frames
  // Byte-flip fuzz: must never crash; decode either fails or succeeds.
  ho::Rng rng(12345);
  for (int i = 0; i < 20000; i++) {
    std::vector<uint8_t> m = f;
    int flips = 1 + (int)rng.below(4);
    for (int j = 0; j < flips; j++) m[rng.below((uint32_t)m.size())] = (uint8_t)rng.next();
    CaptureSink sink;
    (void)ho::decode_frame(m.data(), m.size(), &h, &sink);
  }
  uint8_t big[1100] = {0};
  CHECK(ho::decode_frame(big, sizeof big, &h, &s) == ho::DecodeErr::TooLarge);
}

TEST(codec_writer_unchanged_after_failed_push_and_rtt_rule) {
  uint8_t buf[96];
  ho::FrameWriter w(buf, sizeof buf, 96);
  CHECK(w.begin(hdr(ho::MsgKind::Telemetry, 0, 1)) == ho::Err::Ok);
  ho::ProbeRec bad{1, "gw", ho::ProbeKind::Icmp, ho::Outcome::Timeout, true, 5, false, 0, 0, 0, false, {}};
  CHECK(w.push(bad) == ho::Err::InvalidField);
  ho::ProbeRec ok{1, "gw", ho::ProbeKind::Icmp, ho::Outcome::Success, true, 5, false, 0, 0, 0, false, {}};
  CHECK(w.push(ok) == ho::Err::Ok);
  size_t before = w.len();
  ho::ProbeRec big{1, "a-much-longer-target-id", ho::ProbeKind::Icmp, ho::Outcome::Success, true, 5, false, 0, 0, 0, false, {}};
  ho::Err e = ho::Err::Ok;
  for (int i = 0; i < 4 && e == ho::Err::Ok; i++) e = w.push(big);
  CHECK(e == ho::Err::BufferFull);
  CHECK(w.len() <= 96);
  (void)before;
  size_t n = w.finish();
  CHECK(n <= 96);
  CHECK(!ho::valid_node_id("Node") && !ho::valid_node_id("-x") && ho::valid_node_id("node-01"));
}

// ---------------------------------------------------------------- scheduler

TEST(periodic_is_staggered_deterministic_and_skips_missed) {
  ho::Periodic a, b;
  a.configure(5000, ho::fnv1a("node-01") ^ 1, 0);
  b.configure(5000, ho::fnv1a("node-02") ^ 1, 0);
  CHECK(a.due() != b.due());  // different phases
  ho::Periodic a2;
  a2.configure(5000, ho::fnv1a("node-01") ^ 1, 0);
  CHECK(a.due() == a2.due());  // deterministic
  // Fire normally for 10 periods.
  int fired = 0;
  for (uint32_t t = 0; t < 50000; t += 10) if (a.poll(t)) fired++;
  CHECK(fired == 10 || fired == 9);
  // Sleep through 7 periods: exactly one fire, 6 or 7 counted missed, no burst.
  uint32_t missed_before = a.missed();
  int burst = 0;
  uint32_t t0 = 50000 + 35000;
  for (uint32_t t = t0; t < t0 + 100; t += 10) if (a.poll(t)) burst++;
  CHECK(burst == 1);
  CHECK(a.missed() - missed_before >= 6);
  // Deadlines stay on the period grid (no drift from completion time).
  uint32_t d1 = a.due();
  CHECK(a.poll(d1 + 400));
  uint32_t d2 = a.due();
  CHECK(d2 - d1 >= 5000 - 0 && d2 - d1 <= 5000 + 1250);
}

TEST(periodic_handles_millis_wraparound) {
  ho::Periodic p;
  uint32_t start = 0xFFFFF000u;
  p.configure(1000, 7, start);
  int fired = 0;
  for (uint64_t t = start; t < (uint64_t)start + 10000; t += 5) if (p.poll((uint32_t)t)) fired++;
  CHECK(fired >= 9 && fired <= 10);
}

TEST(token_bucket_enforces_rate_and_burst) {
  ho::TokenBucket b;
  b.configure(600, 1800, 0);
  CHECK(b.try_take(1800, 0));
  CHECK(!b.try_take(1, 0));
  CHECK(!b.try_take(700, 1000));  // only 600 refilled after 1 s
  CHECK(b.try_take(600, 1000));
  // Over 10 s the total admitted can never exceed burst + rate*t.
  b.configure(600, 1800, 0);
  uint32_t admitted = 0;
  for (uint32_t t = 0; t <= 10000; t += 50) if (b.try_take(200, t)) admitted += 200;
  CHECK(admitted <= 1800 + 600 * 10);
  CHECK(admitted >= 600 * 10);
}

TEST(frame_queue_bounded_fifo_with_drop_oldest_and_wrap) {
  ho::FrameQueue<100, 8> q;
  uint8_t d[40], out[64];
  for (int i = 0; i < 40; i++) d[i] = (uint8_t)i;
  CHECK(q.push(d, 40, 0, 1, 1));
  CHECK(q.push(d, 40, 1, 1, 2));
  CHECK(q.push(d, 40, 2, 1, 3));  // must drop seq 1
  CHECK(q.size() == 2 && q.dropped_overflow() == 1);
  CHECK(q.front()->seq == 2);
  CHECK(q.used_bytes() <= 100);
  // The wrapped frame must read back intact.
  q.pop();
  CHECK(q.front()->seq == 3);
  CHECK(q.copy_front(out, sizeof out) == 40 && memcmp(out, d, 40) == 0);
  q.expire(100000, 1000);
  CHECK(q.size() == 0 && q.dropped_expired() == 1);
  uint8_t huge[200] = {0};
  CHECK(!q.push(huge, 200, 0, 1, 9));
  // Randomized model check against a std::vector reference.
  ho::Rng rng(99);
  std::vector<std::vector<uint8_t>> model;
  ho::FrameQueue<256, 6> q2;
  for (int step = 0; step < 5000; step++) {
    if (rng.below(3) != 0) {
      uint16_t len = (uint16_t)(1 + rng.below(90));
      std::vector<uint8_t> v(len);
      for (auto& x : v) x = (uint8_t)rng.next();
      q2.push(v.data(), len, 0, 0, (uint64_t)step);
      model.push_back(v);
      size_t used = 0;
      for (auto& m : model) used += m.size();
      while (model.size() > 6 || used > 256) { used -= model.front().size(); model.erase(model.begin()); }
    } else if (!model.empty()) {
      uint8_t o[128];
      uint16_t n = q2.copy_front(o, sizeof o);
      CHECK(n == model.front().size() && memcmp(o, model.front().data(), n) == 0);
      q2.pop();
      model.erase(model.begin());
    }
    CHECK(q2.size() == model.size());
  }
}

TEST(backoff_bounded_and_jittered) {
  ho::Backoff b(1000, 60000, 5);
  uint32_t prev = 0;
  for (int i = 0; i < 20; i++) {
    uint32_t v = b.next();
    CHECK(v >= 500 && v <= 60000);
    prev = v;
  }
  CHECK(prev >= 30000);
  b.reset();
  CHECK(b.next() <= 1000);
}

TEST(rssi_stats) {
  ho::RssiStats s;
  s.add(-70); s.add(-60); s.add(-80);
  CHECK(s.count == 3 && s.min == -80 && s.max == -60 && s.sum == -210);
}

// ---------------------------------------------------------------- dns

TEST(dns_build_and_classify) {
  uint8_t q[128];
  size_t n = ho::dns_build_query(q, sizeof q, 0x1234, "router.home.arpa", 1);
  CHECK(n == 12 + 18 + 4);
  CHECK(q[12] == 6 && memcmp(q + 13, "router", 6) == 0);
  CHECK(ho::dns_build_query(q, sizeof q, 1, "bad..name", 1) == 0);
  // Build a response: copy query, set QR, ANCOUNT=1, append A record with pointer.
  uint8_t r[128];
  memcpy(r, q, n);
  r[2] = 0x81; r[3] = 0x80; r[7] = 1;
  size_t p = n;
  const uint8_t ans[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10};
  memcpy(r + p, ans, sizeof ans);
  p += sizeof ans;
  const uint8_t ip[4] = {192, 0, 2, 10}, other[4] = {192, 0, 2, 11};
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::Ipv4, ip).answer == ho::DnsAnswer::Match);
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::Ipv4, other).answer == ho::DnsAnswer::Mismatch);
  CHECK(ho::dns_classify(r, p, 0x9999, ho::DnsExpect::Ipv4, ip).error_code == -2);
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::Nxdomain, ip).answer == ho::DnsAnswer::Mismatch);
  r[3] = 0x83;  // NXDOMAIN
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::Nxdomain, ip).answer == ho::DnsAnswer::ExpectedNxdomain);
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::Ipv4, ip).answer == ho::DnsAnswer::UnexpectedNxdomain);
  r[3] = 0x82;
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::AnyAnswer, ip).answer == ho::DnsAnswer::Servfail);
  r[3] = 0x85;
  CHECK(ho::dns_classify(r, p, 0x1234, ho::DnsExpect::AnyAnswer, ip).answer == ho::DnsAnswer::Refused);
  r[3] = 0x80;
  CHECK(ho::dns_classify(r, p - 3, 0x1234, ho::DnsExpect::Ipv4, ip).answer == ho::DnsAnswer::Malformed);
  // Compression-pointer loop must terminate.
  uint8_t loop[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1};
  (void)ho::dns_classify(loop, sizeof loop, 0x1234, ho::DnsExpect::AnyAnswer, ip);
  // Random garbage never crashes.
  ho::Rng rng(7);
  for (int i = 0; i < 20000; i++) {
    uint8_t g[64];
    size_t len = rng.below(64);
    for (size_t j = 0; j < len; j++) g[j] = (uint8_t)rng.next();
    if (len >= 2) { g[0] = 0x12; g[1] = 0x34; }
    (void)ho::dns_classify(g, len, 0x1234, ho::DnsExpect::AnyAnswer, ip);
  }
}

// ---------------------------------------------------------------- hmac

static std::string hex(const uint8_t* d, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += h[d[i] >> 4]; s += h[d[i] & 15]; }
  return s;
}

TEST(sha256_and_hmac_rfc4231) {
  uint8_t out[32];
  ho::Sha256 s;
  s.init();
  s.update((const uint8_t*)"abc", 3);
  s.final(out);
  CHECK(hex(out, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  // RFC 4231 test case 2
  ho::hmac_sha256((const uint8_t*)"Jefe", 4, (const uint8_t*)"what do ya want for nothing?", 28, out);
  CHECK(hex(out, 32) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  // RFC 4231 test case 6 (key longer than block size)
  uint8_t key[131];
  memset(key, 0xaa, sizeof key);
  const char* msg = "Test Using Larger Than Block-Size Key - Hash Key First";
  ho::hmac_sha256(key, sizeof key, (const uint8_t*)msg, strlen(msg), out);
  CHECK(hex(out, 32) == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

static const uint8_t ECHO_KEY[] = "test-echo-key-0123456789abcdef!!";

TEST(udp_echo_matches_rust_golden_and_verifies) {
  uint8_t req[64], resp[64];
  size_t n = ho::echo_build(req, sizeof req, false, "node-01", 7, 0xdeadbeefu, 123456, ECHO_KEY, 32);
  CHECK(n == 4 + 7 + 12 + 16);
  std::vector<uint8_t> want = read_hex("udp_echo_request");
  if (getenv("UPDATE_GOLDEN")) {
    std::string path = golden_dir() + "/udp_echo_request.hex";
    FILE* f = fopen(path.c_str(), "wb");
    if (f) { fprintf(f, "%s\n", hex(req, n).c_str()); fclose(f); }
  } else {
    CHECK(want.size() == n && memcmp(want.data(), req, n) == 0);
  }
  size_t m = ho::echo_build(resp, sizeof resp, true, "node-01", 7, 0xdeadbeefu, 123456, ECHO_KEY, 32);
  CHECK(ho::echo_verify_response(resp, m, "node-01", 7, 0xdeadbeefu, ECHO_KEY, 32));
  CHECK(!ho::echo_verify_response(resp, m, "node-01", 8, 0xdeadbeefu, ECHO_KEY, 32));
  resp[m - 1] ^= 1;
  CHECK(!ho::echo_verify_response(resp, m, "node-01", 7, 0xdeadbeefu, ECHO_KEY, 32));
  CHECK(!ho::echo_verify_response(req, n, "node-01", 7, 0xdeadbeefu, ECHO_KEY, 32));  // request is not a response
}


// ---------------------------------------------------------------- config validation

static ho::ConfigParamsRec good_params(uint64_t rev) {
  ho::ConfigParamsRec p{};
  p.revision = rev; p.report_ms = 2000; p.wifi_link_ms = 5000; p.ap_scan_ms = 120000; p.heartbeat_ms = 10000;
  p.health_ms = 60000; p.egress_bytes_per_sec = 600; p.egress_burst_bytes = 1800; p.max_payload = 1024;
  p.offline_buffer_bytes = 6144; p.flags = ho::cfgflag::kPassiveScan; p.max_probe_inflight = 2; p.scan_max_dwell_ms = 120;
  return p;
}

static ho::ProbeTargetRec target(const char* id, ho::ProbeKind k) {
  ho::ProbeTargetRec t{};
  snprintf(t.id, sizeof t.id, "%s", id);
  t.kind = k; t.addr_source = ho::AddrSource::Gateway; t.interval_ms = 5000; t.timeout_ms = 1000;
  return t;
}

TEST(validate_config_rules) {
  using namespace ho;
  const ConfigLimits esp8266{feature::kWifiSta | feature::kApScan | feature::kIcmp | feature::kUdpEcho | feature::kDns | feature::kTcp, 8, 16, 6144};
  ProbeTargetRec t[3] = {target("gw-icmp", ProbeKind::Icmp), target("srv", ProbeKind::UdpEcho), target("d", ProbeKind::Dns)};
  snprintf(t[2].qname, sizeof t[2].qname, "router.home.arpa");
  CHECK(validate_config(good_params(5), 4, t, 3, 0, esp8266) == reject::kNone);
  CHECK(validate_config(good_params(4), 4, t, 3, 0, esp8266) == reject::kStale);       // same revision
  CHECK(validate_config(good_params(3), 4, t, 3, 0, esp8266) == reject::kStale);       // older revision
  ConfigParamsRec p = good_params(5);
  p.egress_bytes_per_sec = 50000;
  CHECK(validate_config(p, 4, t, 3, 0, esp8266) == reject::kRange);                    // unsafe budget
  p = good_params(5); p.egress_burst_bytes = 100;
  CHECK(validate_config(p, 4, t, 3, 0, esp8266) == reject::kRange);                    // burst < rate
  p = good_params(5); p.offline_buffer_bytes = 16384;
  CHECK(validate_config(p, 4, t, 3, 0, esp8266) == reject::kRange);                    // exceeds arena
  p = good_params(5); p.flags |= cfgflag::kBleScan;
  CHECK(validate_config(p, 4, t, 3, 0, esp8266) == reject::kUnsupported);              // no BLE radio
  p = good_params(5); p.flags |= cfgflag::kCsi;
  CHECK(validate_config(p, 4, t, 3, 0, esp8266) == reject::kUnsupported);
  ProbeTargetRec http[1] = {target("h", ProbeKind::Http)};
  CHECK(validate_config(good_params(5), 4, http, 1, 0, esp8266) == reject::kUnsupported);
  ProbeTargetRec dup[2] = {target("x", ProbeKind::Icmp), target("x", ProbeKind::Icmp)};
  CHECK(validate_config(good_params(5), 4, dup, 2, 0, esp8266) == reject::kMalformed);
  ProbeTargetRec nodns[1] = {target("d", ProbeKind::Dns)};
  CHECK(validate_config(good_params(5), 4, nodns, 1, 0, esp8266) == reject::kMalformed);  // dns needs qname
  ProbeTargetRec slow[1] = {target("s", ProbeKind::Icmp)};
  slow[0].timeout_ms = 5000; slow[0].interval_ms = 4000;
  CHECK(validate_config(good_params(5), 4, slow, 1, 0, esp8266) == reject::kRange);    // timeout >= interval
  CHECK(validate_config(good_params(5), 4, t, 9, 0, esp8266) == reject::kTooMany);
  CHECK(validate_config(good_params(5), 4, t, 3, 17, esp8266) == reject::kTooMany);
}

int main() {
  for (auto& t : registry()) {
    int before = g_failures;
    t.fn();
    printf("%s %s\n", g_failures == before ? "ok  " : "FAIL", t.name);
  }
  printf("\n%d tests, %d checks, %d failures\n", (int)registry().size(), g_checks, g_failures);
  return g_failures ? 1 : 0;
}
