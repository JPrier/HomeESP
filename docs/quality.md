# Quality gates

CI (`.github/workflows/ci.yml`) runs on every push and PR:

| Job | Gates |
|---|---|
| rust | `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --locked`; `ho-protocol` builds for `thumbv7em-none-eabihf` (proves `no_std`); architecture rules (`tools/check_architecture.sh`); scenario sweep S01–S17 × 5 seeds; golden vectors unchanged |
| supply-chain | `cargo-deny`: advisories, bans (no wildcards), licenses (allowlist), sources |
| firmware-host | portable firmware core under ASan + UBSan (g++), and with clang |
| firmware-build | PlatformIO build of `esp8266-4m`; RAM < 70%, flash < 60% budget gate; artifact upload |
| dashboard | ESLint (strict, zero warnings), `tsc` strict, Vitest, production build, no external URLs in the bundle |
| tools | ruff, pytest (provisioning validation, size gate, UDP relay) |
| e2e | real mosquitto with passwords + ACL → server → SQLite → API; durable ACK received; duplicate detected; cross-node publish and bad password refused |
| image | multi-stage container build; simulator smoke inside the image with networking disabled |

Workspace lints deny `unwrap`, `expect`, `panic`, `dbg!`, `todo!` and `unsafe` in
production code (tests opt in explicitly). Allowed style lints, with reason:
`too_many_arguments` (storage upserts mirror table columns), `type_complexity` (rollup
accumulators), `field_reassign_with_default` (report builders). The protocol crate
additionally warns on indexing and truncating casts.

Coverage tooling is not wired into CI; critical reducers are instead covered by
invariant/property tests and the 17-scenario multi-seed sweep. That is a known gap
against the spec's suggested 90% branch target.
