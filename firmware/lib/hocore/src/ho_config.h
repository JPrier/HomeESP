// Validation of server-desired configuration against node capabilities and safe
// ranges. Pure function: host-tested. A rejected config never replaces the
// last-known-good one.
#pragma once
#include <stdint.h>
#include <string.h>

#include "ho_codec.h"

namespace ho {

struct ConfigLimits {
  uint32_t features;        // capability bits this node really has
  uint8_t max_targets;
  uint8_t max_bssids;
  uint16_t offline_arena;   // bytes available for the offline telemetry buffer
};

// Returns reject::kNone when acceptable, otherwise a reject reason code.
inline uint8_t validate_config(const ConfigParamsRec& p, uint64_t current_revision, const ProbeTargetRec* targets,
                               uint8_t target_count, uint8_t bssid_count, const ConfigLimits& lim) {
  if (p.revision <= current_revision) return reject::kStale;
  auto in = [](uint32_t v, uint32_t lo, uint32_t hi) { return v >= lo && v <= hi; };
  if (!in(p.report_ms, 500, 60000) || !in(p.wifi_link_ms, 1000, 600000) || !in(p.heartbeat_ms, 1000, 120000) ||
      !in(p.health_ms, 10000, 600000))
    return reject::kRange;
  if (p.ap_scan_ms != 0 && !in(p.ap_scan_ms, 30000, 3600000)) return reject::kRange;
  if (!in(p.egress_bytes_per_sec, 100, 4000) || p.egress_burst_bytes < p.egress_bytes_per_sec || p.egress_burst_bytes > 8000)
    return reject::kRange;
  if (!in(p.max_payload, 256, kMaxFrame) || p.offline_buffer_bytes > lim.offline_arena) return reject::kRange;
  if (!in(p.max_probe_inflight, 1, 2) || !in(p.scan_max_dwell_ms, 50, 300)) return reject::kRange;
  if ((p.flags & cfgflag::kBleScan) && !(lim.features & feature::kBle)) return reject::kUnsupported;
  if ((p.flags & cfgflag::kCsi) && !(lim.features & feature::kCsi)) return reject::kUnsupported;
  if ((p.flags & cfgflag::kPassiveScan) && !(lim.features & feature::kApScan)) return reject::kUnsupported;
  if (target_count > lim.max_targets || bssid_count > lim.max_bssids) return reject::kTooMany;
  for (uint8_t i = 0; i < target_count; i++) {
    const ProbeTargetRec& t = targets[i];
    if (!in(t.interval_ms, 1000, 3600000) || !in(t.timeout_ms, 100, 5000) || t.timeout_ms >= t.interval_ms) return reject::kRange;
    if (t.dscp > 63) return reject::kRange;
    uint32_t need = 0;
    switch (t.kind) {
      case ProbeKind::Icmp: need = feature::kIcmp; break;
      case ProbeKind::UdpEcho: need = feature::kUdpEcho; break;
      case ProbeKind::Dns: need = feature::kDns; break;
      case ProbeKind::Tcp: need = feature::kTcp; break;
      case ProbeKind::Http: return reject::kUnsupported;
    }
    if (!(lim.features & need)) return reject::kUnsupported;
    if (t.kind == ProbeKind::Dns && t.qname[0] == 0) return reject::kMalformed;
    if (t.kind == ProbeKind::Tcp && t.port == 0) return reject::kMalformed;
    if (t.addr_source == AddrSource::Literal && t.ipv4[0] == 0) return reject::kMalformed;
    for (uint8_t j = 0; j < i; j++)
      if (strcmp(targets[j].id, t.id) == 0) return reject::kMalformed;
  }
  return reject::kNone;
}

}  // namespace ho
