# Security and privacy

## Threats and controls

| Threat | Control | Test |
|---|---|---|
| Forged / spoofed telemetry | unique per-node broker credentials; ACL pins each node to `nodes/<own id>/…`; server accepts only registered node ids and requires envelope id = topic id | `broker_e2e.sh` (ACL), `api.rs` (spoof), S14 |
| Service account abusing ACL `pattern` rules | `observatory-server`/`homeassistant` are reserved and rejected as node ids | config tests |
| Malicious payloads | size check before decode; total decoder (fuzz/property tests in Rust and C++); bounded record counts | `robustness.rs`, host tests |
| Replay | per-(node, boot) dedup + DB unique key; UDP echo sliding anti-replay window | `seq.rs`, `echo.rs` |
| Unbounded state from node input | unknown probe targets dropped; ≤ 32 targets per vantage; forward sequence jumps capped; timestamps clamped | logic tests |
| UDP amplification | responses same size as requests; no reply to unauthenticated/replayed/over-budget requests; LAN bind | `echo.rs` tests |
| API abuse | bearer roles (viewer/operator), constant-time compare, typed errors, 256 KB body limit, allowlisted metrics targets and diagnostic jobs (no arbitrary hosts/URLs), bounded ranges | `api.rs` |
| Secret exfiltration via config edits | `server`, `mqtt`, notifiers, integrations, watchdog and `site_id` are immutable over HTTP; config writes disabled in simulate mode | `api.rs` (`locked_section`) |
| SSRF through probes | HTTP checks only to configured host/path, redirects never followed, body capped | `probes.rs` tests |
| Supply chain | pinned toolchain/images, lockfiles, `cargo-deny` (advisories, licenses, sources) | CI |
| Node credential theft | **ESP8266 has no flash encryption**: anyone with physical access can read LittleFS. Mitigation: per-node credentials revocable at the broker (`mosquitto_passwd -D`) | documented limitation |
| API bearer token over plain HTTP on the LAN | the server speaks HTTP; tokens are sniffable on the LAN segment. Mitigations: API port limited to management hosts by firewall; viewer vs operator tokens; put a TLS reverse proxy in front or use a VPN for anything beyond a trusted LAN | documented limitation |
| Plaintext MQTT on LAN | firmware 0.1.x has no TLS; broker listener bound to LAN + firewall-scoped; production template uses TLS 8883 for capable clients | documented limitation |

## Privacy

- No packet payload capture, no browsing DNS logging (probes use only configured names),
  no audio, no guest identifiers.
- AP scans export only **tracked** BSSIDs (configured, or same-SSID household
  infrastructure); other networks contribute anonymous per-channel counts only.
- BLE: nodes would emit only enrolled devices. The server discards BLE data when
  location is disabled, for non-consenting devices and after revocation (counted).
- Revocation (`DELETE /api/v1/devices/{id}`) purges live state, BLE windows, location
  history and calibration rows, and removes HA entities. Exported data and existing
  backups are outside that purge (rotate backups per retention policy).
- Location history is operator-only; device matcher material is never returned by the API.
- Location is **off by default** and never published to HA unless explicitly enabled.
