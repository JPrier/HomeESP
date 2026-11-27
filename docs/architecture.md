# Architecture

## Layers and boundaries

`service → logic → data → dependency` (spec §1.1) maps onto crates:

| Layer | Crates | Rules (enforced by `tools/check_architecture.sh` in CI) |
|---|---|---|
| Wire contract | `ho-protocol` | `no_std`, zero dependencies, no allocation, total decoder |
| Domain | `ho-domain` | types + config validation; no IO, no clocks |
| Pure logic | `ho-logic` | reducers take time/config/observations as input; no IO, clocks or globals |
| Data | `ho-storage` | SQLite behind a typed API; one writer thread |
| Adapters | `ho-collectors`, `ho-integrations` | network IO, each bounded by timeouts |
| Service | `ho-server`, `ho-cli` | composition, scheduling, HTTP, MQTT |

The **engine** (`ho_logic::engine::Engine`) is the heart: `apply(Input) -> Vec<Effect>`.
Inputs are normalized observations, broker status, ingestion health, ticks and operator
actions — each carrying its own timestamp. Effects are liveness/health changes,
incident lifecycle events, notifications, location estimates and purges. The server
performs effects (persist atomically, enqueue outbox, broadcast SSE, publish HA); the
simulator drives the *same* engine with a fake clock, so the S01–S17 scenarios
exercise production logic, not a model of it.

## Data flow

1. Node samples with its monotonic clock and batches records into ≤1024-byte frames;
   critical lifecycle events go in a separate frame flagged `NEEDS_ACK`.
2. Broker authenticates the node (unique credentials) and restricts it to its own
   topic subtree (ACL).
3. Server ingestion: topic must name a registered node → size checked *before*
   decoding → per-node rate limit (telemetry shed first) → total decode → envelope
   node id must equal topic node id → per-boot sequence tracking → time mapping
   (min-delay offset, uncertainty) → normalization.
4. Frame + observations committed in one SQLite transaction keyed on
   `(site, node, boot, sequence)`; duplicates are no-ops. **Only then** is the
   application ACK published.
5. Engine reducers update state; derived state + outbox rows commit together.
6. Outbox deliverer sends notifications with capped exponential backoff and records
   every attempt; HA states are published on change only.

## Correlation

`ho_logic::incidents::correlate` is a deterministic rule set (spec §12.3) producing
hypotheses with supporting evidence, contradicting evidence, alternatives, a
confidence *class* (never an invented probability) and a next diagnostic step.
Child symptoms explained by a broader cause (nodes behind a failed AP) are grouped as
evidence instead of opening separate incidents. Statistical guards — a 99% Wilson
lower bound on loss and a two-vantage corroboration rule — keep fleet-scale random
loss from paging anyone (found and tuned via the multi-seed scenario sweep; see
[ADR 0004](adr/0004-statistical-guards.md)).

## Decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-esp8266-cpp-firmware.md) | ESP8266 firmware in C++ (Arduino core) with a Rust-mirrored protocol |
| [0002](adr/0002-wire-protocol.md) | Hand-specified TLV wire format with golden vectors |
| [0003](adr/0003-storage-sqlite.md) | SQLite WAL, single writer, histogram rollups |
| [0004](adr/0004-statistical-guards.md) | Wilson-bound loss rule and corroboration |
| [0005](adr/0005-app-level-ack.md) | Application-level durable ACK; node publishes at QoS 0 |
| [0006](adr/0006-deployment-host-networking.md) | Compose with host networking behind the host firewall |
