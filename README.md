# Home Observatory

Local-first home network observability and spatial intelligence. Inexpensive Wi‑Fi
boards around the home act as monitoring vantage points; a small central service
correlates what they see with a wired baseline, explains failures as evidence-backed
hypotheses, and exposes history, a dashboard, Home Assistant entities and alerts.
No cloud, no LLM, no packet capture, no covert tracking.

```
ESP8266 nodes ──MQTT (per-node creds + ACL)──▶ broker ──▶ observatory-server ──▶ SQLite (WAL)
  probes: gateway/server ICMP,                         │  pure engine: health, incidents,
  authenticated UDP echo, DNS w/ answer check,         │  correlation, localization
  passive AP scans, health                             ├─▶ HTTP API + dashboard + SSE
wired central checks (ICMP/TCP/DNS/HTTP) ─────────────▶├─▶ durable outbox ─▶ ntfy / webhook
                                                       └─▶ Home Assistant MQTT discovery
```

## What works (verified)

| Area | Status | Evidence |
|---|---|---|
| 3 × ESP8266EX nodes on real Wi‑Fi, reporting to a real broker | **running** | [test report](docs/test-report.md#hardware) |
| Wire protocol v1 (Rust `no_std` + C++), byte-identical | PASS | shared golden vectors, both test suites |
| Durable ingestion, dedup, durable ACK of critical events | PASS | unit, integration and real-broker E2E tests |
| Network probes from nodes + wired baseline | PASS (live) | dashboard / `/api/v1/site/status` |
| Incident correlation S01–S17 | PASS (simulated, 30 seeds) | `observatory-cli sim all` |
| Room-level BLE localization | PASS in simulation only | boards have **no BLE radio** — see below |
| Dashboard, API, HA discovery, notifier outbox | PASS (tests) | `dashboard/`, `crates/server/tests` |

**Hardware reality:** the boards in this deployment are **ESP8266EX** (4 MB flash,
2.4 GHz Wi‑Fi only, no Bluetooth), not ESP32. Firmware is therefore C++ on the Arduino
core ([ADR 0001](docs/adr/0001-esp8266-cpp-firmware.md)); BLE presence features are
implemented server-side and validated in simulation but cannot run on these boards.
See the [hardware matrix](docs/hardware.md).

## Quickstart (no hardware, no credentials)

```sh
# Build and run all checks
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
firmware/test/host/run.sh                      # C++ firmware core, golden vectors
(cd dashboard && npm ci && npm run lint && npm run typecheck && npm test && npm run build)

# Simulated end-to-end demo: synthetic nodes + scripted faults, no network probing
docker compose -f deploy/compose.sim.yaml up --build
#   -> http://127.0.0.1:18090  token: sim-viewer-token-00000000000000

# Or without Docker
observatory-server --config configs/sim-demo.yaml --simulate
observatory-cli sim all --seeds 5              # every fault scenario, several seeds
observatory-cli replay --input tests/fixtures/scenario-ap-failure.jsonl
```

## Production

1. Write your site config from [`configs/site.example.yaml`](configs/site.example.yaml)
   and validate it: `observatory-cli config validate --file site.yaml`.
2. Create secrets (broker passwords, API tokens, echo keys) — [operations guide](docs/operations.md#secrets).
3. `OBS_DIR=/srv/observatory docker compose -f deploy/compose.yaml up -d broker server`
4. Open the documented firewall ports (LAN only) — [operations](docs/operations.md#firewall).
5. Flash and provision each board over USB: `python tools/esp.py flash --port COM5`
   then `python tools/esp.py provision --port COM5 --node node-01 --secrets nodes.json`.

## Repository

| Path | Contents |
|---|---|
| `crates/protocol` | wire format v1 (`no_std`, allocation-free) |
| `crates/domain` | IDs, config schema + validation, observation model |
| `crates/logic` | pure reducers: time sync, stats, health, incidents, localization, engine |
| `crates/storage` | SQLite persistence, rollups, outbox, retention, backup |
| `crates/collectors` | central probes, UDP echo responder, OPNsense + SNMP adapters |
| `crates/integrations` | Home Assistant discovery, notifiers, Prometheus, watchdog |
| `crates/server` | service composition, MQTT ingestion, API, jobs |
| `crates/simulator` | deterministic world + scenarios S01–S17 |
| `crates/cli` | `observatory-cli` |
| `firmware/` | ESP8266 firmware (PlatformIO) + portable core with host tests |
| `dashboard/` | React + TypeScript dashboard (no CDN, no analytics) |
| `deploy/` | Dockerfile, Compose, broker config + ACL |
| `tools/` | board flashing/provisioning, CH340 driver workaround, dev relay |
| `docs/` | architecture, ADRs, protocol, hardware, operations, security, test report |

## Documentation

[Architecture](docs/architecture.md) · [ADRs](docs/adr/) · [Protocol](docs/protocol.md) ·
[Hardware](docs/hardware.md) · [Operations & runbook](docs/operations.md) ·
[Security & privacy](docs/security.md) · [Quality gates](docs/quality.md) ·
[Test & acceptance report](docs/test-report.md) · [API (OpenAPI)](docs/openapi.json)
