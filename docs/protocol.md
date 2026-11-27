# Wire protocol v1

Authoritative implementation: `crates/protocol` (Rust, `no_std`). Firmware mirror:
`firmware/lib/hocore/src/ho_codec.*`. Golden vectors: `tests/golden/protocol/*.hex`
(regenerate deliberately with `UPDATE_GOLDEN=1 cargo test -p ho-protocol --test golden`;
any diff is a wire change).

## Frame

All integers little-endian. Max frame 1024 bytes (rejected before decoding if larger).

| Field | Type | Notes |
|---|---|---|
| magic | `"HO"` | |
| schema | u16 | `1`; other versions rejected with a counted reason |
| kind | u8 | 1 telemetry, 2 events, 3 status, 4 capabilities, 5 config/reported, 16 config/desired, 17 ack |
| flags | u8 | bit0 NEEDS_ACK, bit1 MORE_FRAGMENTS, bit2 REPLAYED |
| node_id | u8 len + bytes | `[a-z0-9-]{1,32}`; must equal the topic's node id |
| boot_id | 16 bytes | random per boot (hardware RNG) |
| sequence | u64 | monotonic per boot across all kinds; dedup key with site/node/boot |
| sent_mono_ms | u64 | node monotonic clock at send |
| config_revision | u64 | applied desired-config revision |
| record_count | u8 | |
| records | `type u8, len u16, payload` | |

Decoding is total: every input yields a frame or one of 12 counted error classes. A
frame is fully validated before any record reaches a consumer.

## Records

| Type | Record | Key fields |
|---:|---|---|
| 1 | WifiLink | age, status, RSSI (optional), channel, BSSID (optional), association generation |
| 2 | ApScan | scan id, duration, complete/partial/skipped, 14 per-channel beacon counts, tracked BSSIDs only |
| 3 | Probe | target id, kind (icmp/udp_echo/dns/tcp/http), outcome (8 classes), RTT µs **only on success**, scan-overlap, DSCP, scheduling lateness, error code, optional DNS rcode/answer/transport/qtype |
| 4 | Lifecycle | event (boot, wifi/mqtt up/down, config applied/rejected, BSSID change, DHCP change, data gap), raw SDK reason, prior/new BSSID, duration |
| 5 | System | uptime, heap free/min/max-block/fragmentation, reset reason, queue fill, drop counters by reason, missed schedules, loop lag, reconnects, tx bytes/frames, firmware version |
| 6 | BleSummary | enrolled opaque device id, window, count, RSSI min/max/sum, last-seen age, scanner coverage |
| 7 | Sensor | sensor id, kind, unit, value ×1000, quality, calibration revision |
| 8 | Capabilities | chip, flash, RAM, feature bits, firmware, profile, limits |
| 9 | ConfigStatus | revision, applied/rejected/pending, reason |
| 10 | NodeStatus | online, reason, uptime (the broker last-will is the literal text `offline`) |
| 16 | ConfigParams | revision, intervals, egress budget, payload/buffer limits, scan dwell, feature flags |
| 17 | ProbeTarget | id, kind, address source (literal/gateway/assigned resolver/server), port, interval, timeout, DSCP, DNS expectation, qname |
| 18 | TrackedBssid | 6 bytes |
| 19 | Ack | boot id + sequence of the durably stored events frame |

Unknown record types are skipped; records longer than this version knows keep their
known prefix (additive evolution). Anything else requires `SCHEMA_VERSION` 2.

## Topics (`observatory/v1/{site}`)

| Suffix | Direction | QoS / retain |
|---|---|---|
| `/nodes/{id}/telemetry` | node → server | 0 / no |
| `/nodes/{id}/events` | node → server | 0 / no — durability via application ACK ([ADR 0005](adr/0005-app-level-ack.md)) |
| `/nodes/{id}/status` | node → server | 0 / yes; LWT `offline` (QoS 1, retained) |
| `/nodes/{id}/capabilities` | node → server | 0 / yes |
| `/nodes/{id}/config/reported` | node → server | 0 / yes |
| `/nodes/{id}/config/desired` | server → node | 1 / yes, revisioned |
| `/nodes/{id}/ack` | server → node | 1 / no |

## UDP echo

`"HE" | 1 | node_len | node_id | seq u32 | nonce u32 | mono u32 | HMAC-SHA256[..16]`.
The response is identical in size with magic `"HR"` and a fresh MAC (no amplification).
The responder checks MAC, a per-node sliding anti-replay window on `seq` (reboots are
accepted after 30 s of silence), then a per-node token bucket; failures get no reply.
Golden vector: `tests/golden/protocol/udp_echo_request.hex` (C++ and Rust agree).
