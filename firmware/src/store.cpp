#include "store.h"

#include <LittleFS.h>
#include <string.h>

namespace node {

uint32_t crc32(const uint8_t* d, size_t n) {
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) {
    c ^= d[i];
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
  }
  return ~c;
}

template <typename T>
static bool load(const char* path, T* out, uint32_t magic) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  bool ok = f.size() == sizeof(T) && f.read((uint8_t*)out, sizeof(T)) == sizeof(T);
  f.close();
  if (!ok || out->magic != magic) return false;
  return crc32((const uint8_t*)out, offsetof(T, crc)) == out->crc;
}

template <typename T>
static bool save(const char* path, T* v, uint32_t magic) {
  v->magic = magic;
  v->crc = crc32((const uint8_t*)v, offsetof(T, crc));
  String tmp = String(path) + ".tmp";
  File f = LittleFS.open(tmp, "w");
  if (!f) return false;
  bool ok = f.write((const uint8_t*)v, sizeof(T)) == sizeof(T);
  f.close();
  if (!ok) { LittleFS.remove(tmp); return false; }
  LittleFS.remove(path);
  return LittleFS.rename(tmp, path);
}

bool store_begin() {
  if (LittleFS.begin()) return true;
  // First boot on a fresh board: format the dedicated FS partition (not the app).
  return LittleFS.format() && LittleFS.begin();
}

bool secrets_load(Secrets* s) {
  memset(s, 0, sizeof(*s));
  if (load("/secrets.bin", s, kSecretsMagic)) return true;
  memset(s, 0, sizeof(*s));
  s->mqtt_port = 1883;
  s->echo_port = 47019;
  strncpy(s->site, "home", sizeof(s->site) - 1);
  return false;
}

bool secrets_save(Secrets* s) { return save("/secrets.bin", s, kSecretsMagic); }

bool secrets_complete(const Secrets& s, const char** missing) {
  if (!s.wifi_ssid[0]) { *missing = "wifi_ssid"; return false; }
  if (!ho::valid_node_id(s.node_id)) { *missing = "node_id"; return false; }
  if (!ho::valid_node_id(s.site)) { *missing = "site"; return false; }
  if (!s.mqtt_host[0]) { *missing = "mqtt_host"; return false; }
  if (!s.mqtt_user[0] || !s.mqtt_pass[0]) { *missing = "mqtt_user/mqtt_pass"; return false; }
  return true;
}

void config_defaults(NodeConfig* c) {
  memset(c, 0, sizeof(*c));
  ho::ConfigParamsRec& p = c->params;
  p.revision = 0;
  p.report_ms = 2000;
  p.wifi_link_ms = 5000;
  p.ap_scan_ms = 120000;
  p.heartbeat_ms = 10000;
  p.health_ms = 60000;
  p.egress_bytes_per_sec = 600;
  p.egress_burst_bytes = 1800;
  p.max_payload = 1024;
  p.offline_buffer_bytes = 6144;
  p.flags = ho::cfgflag::kPassiveScan;
  p.max_probe_inflight = 2;
  p.scan_max_dwell_ms = 120;
  // Baseline probes that need no site knowledge: gateway and central server.
  ho::ProbeTargetRec& g = c->targets[0];
  strncpy(g.id, "gw-icmp", sizeof(g.id) - 1);
  g.kind = ho::ProbeKind::Icmp;
  g.addr_source = ho::AddrSource::Gateway;
  g.interval_ms = 5000;
  g.timeout_ms = 1000;
  ho::ProbeTargetRec& s = c->targets[1];
  strncpy(s.id, "server-icmp", sizeof(s.id) - 1);
  s.kind = ho::ProbeKind::Icmp;
  s.addr_source = ho::AddrSource::Server;
  s.interval_ms = 5000;
  s.timeout_ms = 1000;
  ho::ProbeTargetRec& e = c->targets[2];
  strncpy(e.id, "server-udp", sizeof(e.id) - 1);
  e.kind = ho::ProbeKind::UdpEcho;
  e.addr_source = ho::AddrSource::Server;
  e.port = 0;  // 0 = provisioned echo_port
  e.interval_ms = 10000;
  e.timeout_ms = 1000;
  c->target_count = 3;
}

bool config_load(NodeConfig* c) {
  if (load("/config.bin", c, kConfigMagic) && c->target_count <= kMaxTargets && c->bssid_count <= kMaxBssids) return true;
  config_defaults(c);
  return false;
}

bool config_save(NodeConfig* c) { return save("/config.bin", c, kConfigMagic); }

bool store_factory_reset() {
  LittleFS.remove("/secrets.bin");
  LittleFS.remove("/config.bin");
  return true;
}

}  // namespace node
