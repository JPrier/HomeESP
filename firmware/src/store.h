// Persistent secrets and last-known-good configuration on LittleFS.
// Secrets and config live in separate files; secrets are never printed.
// ESP8266 has no flash encryption: anyone with physical access to the board can
// read these files. This limitation is documented in docs/security.md.
#pragma once
#include <stdint.h>

#include "ho_codec.h"

namespace node {

constexpr uint32_t kSecretsMagic = 0x484F5331;  // "HOS1"
constexpr uint32_t kConfigMagic = 0x484F4331;   // "HOC1"
constexpr int kMaxTargets = 8;
constexpr int kMaxBssids = 16;

struct Secrets {
  uint32_t magic;
  char wifi_ssid[33];
  char wifi_psk[65];
  char node_id[33];
  char site[17];
  char mqtt_host[64];
  uint16_t mqtt_port;
  char mqtt_user[33];
  char mqtt_pass[65];
  uint8_t echo_key[32];
  uint8_t echo_key_len;
  uint16_t echo_port;
  uint32_t crc;
};

struct NodeConfig {
  uint32_t magic;
  ho::ConfigParamsRec params;
  ho::ProbeTargetRec targets[kMaxTargets];
  uint8_t target_count;
  uint8_t bssids[kMaxBssids][6];
  uint8_t bssid_count;
  uint32_t crc;
};

uint32_t crc32(const uint8_t* d, size_t n);

bool store_begin();
bool secrets_load(Secrets* s);
bool secrets_save(Secrets* s);
bool secrets_complete(const Secrets& s, const char** missing);
bool config_load(NodeConfig* c);
bool config_save(NodeConfig* c);  // write temp then rename: atomic last-known-good
void config_defaults(NodeConfig* c);
bool store_factory_reset();

}  // namespace node
