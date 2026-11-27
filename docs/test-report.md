# Test, performance and acceptance report

Date: 2026-11-27. Statuses follow spec §21: PASS / FAIL / NOT RUN / BLOCKED / NOT APPLICABLE.
"Simulated" means verified against the deterministic simulator driving the production
engine — not field-verified.

## Automated test inventory

| Suite | Count | Result |
|---|---:|---|
| Rust workspace (`cargo test --workspace --locked`) — unit, property, golden, storage, collectors, integrations, server API integration, CLI, scenarios | 115 tests | PASS |
| Firmware core host tests (C++17, `-Werror`, ASan/UBSan in CI) incl. desired-config validation | 18 tests / 6,943 checks | PASS |
| Dashboard (Vitest + Testing Library) | 12 tests | PASS |
| Python tools (pytest) | 4 tests | PASS |
| Scenario sweep S01–S17 | 17 scenarios × 30 seeds = 510 runs | PASS (0 failures) |
| Real-broker E2E (`tests/e2e/broker_e2e.sh`) | 1 scripted run | PASS in CI after fixture fix (see CI) |
| Static gates | rustfmt, clippy `-D warnings`, ESLint strict, `tsc` strict, ruff, architecture rules, cargo-deny | PASS |

Property/fuzz-style coverage: Rust decoder totality (2,000 random inputs + mutation of
valid frames + every truncation), C++ decoder (20,000 byte-flip mutations, every
truncation), DNS classifier (20,000 random packets, compression-loop guard), sequence
redelivery invariants, time mapping never in the future, loss always in [0, 100].

## Hardware

| Item | Result |
|---|---|
| Boards | 3 × ESP8266EX 4 MB (identified via esptool; **not ESP32**) |
| Original flash | all three 4 MB images backed up before overwrite (kept off-repo) |
| Flash / provision over USB on Windows with clone CH340 driver bug | PASS via `tools/ch340_shim.py` |
| Wi‑Fi association (2.4 GHz WPA2) | PASS on all 3 |
| MQTT with per-node credentials + ACL to the production broker | PASS on all 3 |
| Probes: gateway ICMP, server ICMP, authenticated UDP echo, DNS with answer validation | PASS (live data) |
| Passive AP scan, radio coordination (probes skipped, not lost, during scans) | PASS |
| Desired config revision applied and reported | PASS (rev 2 applied) |
| Durable event ACK round trip | PASS (258+ events acked) |
| Field bugs found and fixed | lwmqtt −9 on blocking ops (QoS 0 publishes, ack-first subscribe); modem sleep inflating RTT; scan-channel link samples; reconnect storm on lossy link (10 s command timeout, flap-aware backoff, fw 0.1.3) |
| 24 h soak | NOT RUN (deployment is hours old; see live metrics to continue) |
| BLE enrollment / room accuracy on hardware | BLOCKED — boards have no BLE radio |
| OTA | NOT APPLICABLE on this profile (USB update only; reported in capabilities) |

## Measured performance (production, 3 nodes)

| Metric | Measured | Target |
|---|---|---|
| Application payload | ~135 B/s total (~45 B/s per node) from telemetry+events+health | ≤ 600 B/s/node; ≤ 50 kbps site — PASS (IP/TLS/Wi‑Fi overhead not measured) |
| Ingest → state | lag of last frame ~1.4 s (event-time to receipt, includes 2 s batching) | p95 ≤ 3 s — PASS (point measurement) |
| Server footprint | 0.9% CPU, 3.3 MiB RSS; broker 0.1% CPU, 1 MiB | 2 vCPU / 2 GiB — PASS |
| Storage | 20 MB for ~46k frames / 51k probe rows (incl. migrated history); ~6.6k probe rows/hour | budget 2 GB default |
| Detection (simulated) | node missing 30–35 s; critical target 15 s at 5 s cadence | ≤ 35 s / ≤ 30 s — PASS (simulated) |
| Engine throughput (S16, 40 nodes / 30 devices, release) | ≫ 10× real-time ingest rate | PASS (simulated) |
| Wired baseline | gateway ICMP median 0.44 ms | — |
| Wireless vantages | gateway median 6–15 ms, p95 13–45 ms; 0–19% timeouts on the weakest node | — |
| Monitoring side-effect on LAN RTT/loss | NOT RUN (needs a controlled before/after trial) | ≤ 2 ms, ≤ 0.1 pp |

## Scenario results (simulated, 30 seeds each)

| ID | Expectation | Result |
|---|---|---|
| S01 | no spurious incident on a healthy day; room accuracy recorded | PASS — accuracy 1.00, coverage 1.00 on simulated held-out windows (idealized RF model) |
| S02 | one grouped AP/uplink hypothesis incl. roamed nodes; recovery | PASS |
| S03 | radio issue, not chassis failure | PASS |
| S04 | single node missing, cause unknown, no AP claim, ≤ 35 s | PASS |
| S05 | DNS incident, no WAN claim | PASS |
| S06 | wireless-only DNS → client-path hypothesis | PASS |
| S07 | wireless vs shared wired congestion distinguished | PASS |
| S08 | WAN incident, local DNS not blamed | PASS |
| S09 | observability incident only; bounded buffers; no flood; recovery | PASS |
| S10 | duplicates/reordering/reboot: no duplicate history or incidents | PASS |
| S11 | phone left behind ≠ person location | PASS |
| S12 | boundary: ≤ 2 flips/5 min; stale → not_observed | PASS |
| S13 | revocation purges; buffered BLE after revocation discarded | PASS |
| S14 | malformed/oversized/spoofed/unregistered rejected; traffic continues | PASS |
| S15 | restart mid-incident: ids never reused; condition re-detected | PASS |
| S16 | 40/30 stress + synchronized reboot: no incidents, all online | PASS |
| S17 | experiments disabled by default | PASS (capacity tests NOT APPLICABLE: not implemented) |

## Acceptance matrix (§21)

| ID | Requirement | Status | Evidence / notes |
|---|---|---|---|
| A01 | Fresh checkout runs safe simulation + UI without credentials | PASS | `observatory-server --simulate` (smoke-tested), Compose `simulation` profile, CI image smoke |
| A02 | Firmware builds; bounded scheduling/buffers | PASS | CI firmware build + size gate; host tests of scheduler/token bucket/queue; hardware running |
| A03 | Authenticated, versioned, deduplicated ingestion; durable ACK | PASS | `api.rs`, `broker_e2e.sh`, storage tests, hardware ACKs |
| A04 | Distributed gateway/server/DNS/UDP probes + wired baseline | PASS | live production data |
| A05 | AP/service outage groups symptoms, reports recovery | PASS (simulated) | S02–S08; live: node-missing + wireless-path incidents opened on real conditions |
| A06 | OPNsense/SNMP read-only collectors work or report unsupported | PASS (fixtures) / NOT RUN (live) | parsers + client implemented; no API key configured (deliberately not created); SNMPv3 unsupported |
| A07 | Calibrated room inference with unknown/stale | PASS (simulated) / BLOCKED (hardware) | S01, S11–S13; no BLE on ESP8266 |
| A08 | Unknown BLE discarded; revocation; security verified | PASS | S13, `api.rs`, `security.md`, cargo-deny |
| A09 | History, rollups, retention, backup/restore | PASS | storage tests, CLI backup tests, production migration via online backup |
| A10 | Floor plan, coverage, topology, incident, diagnostics UI | PASS (tests + build) | dashboard; floor plan shows only configured polygons (none invented for the real site) |
| A11 | HA optional/independent; alerts durable | PASS (fixtures) / NOT RUN (real HA) | discovery/availability tests; outbox tests; no HA instance verified |
| A12 | Traffic bounded; no uncontrolled scanning/speed tests | PASS | token bucket tests; ~45 B/s/node measured; passive scans only; no throughput tests exist |
| A13 | Failure recovery without silent loss or retry storms | PASS (simulated) + field fix | S09/S10/S15/S16; reconnect storm found on hardware and fixed (fw 0.1.3) |
| A14 | Deployment, provisioning, updates, runbook reproducible | PASS | deployed to the home server via Compose; `operations.md`; OTA not applicable |
| A15 | Optional sensing isolated, disabled by default | PASS | S17; config validation rejects CSI unless `experimental.csi` |

## Known limitations

- ESP8266: no BLE, no TLS (plaintext MQTT on LAN, firewall-scoped), no flash encryption, no OTA.
- The HTTP API is plain HTTP: bearer tokens travel unencrypted on the LAN (firewall limits the port to management hosts; use a TLS proxy/VPN otherwise).
- Localization accuracy is simulated only; the RF model is idealized.
- Loss thresholds are conservative (99% Wilson bound); ~7% loss over 150 probes is needed to flag degradation.
- Not run: 24 h soak, monitoring side-effect trial, live OPNsense/SNMP/HA, external watchdog, notifier to a real endpoint (only a local webhook sink was used).
- Coverage percentage tooling is not wired into CI.
