# ADR 0001: ESP8266 firmware in C++ with a Rust-mirrored protocol

**Status:** accepted · 2026-11-26

## Context
The spec prefers Rust firmware via `esp-idf-svc`. The boards actually installed are
ESP8266EX (Xtensa LX106, 80 KB RAM, Wi‑Fi only). `esp-idf-svc`/`esp-idf-hal` target
ESP32-family chips only, and no maintained Rust Wi‑Fi stack exists for the ESP8266
(the old `esp8266-hal` has no networking; `esp-wifi` dropped the chip).

## Decision
Firmware is C++17 on the ESP8266 Arduino core (PlatformIO, pinned platform
`espressif8266@4.2.1`). All protocol, scheduling, rate-limiting, buffering, DNS and
HMAC logic lives in a portable, allocation-free core (`firmware/lib/hocore`) that is
compiled and tested on the host with `-Werror` and ASan/UBSan. The Rust `ho-protocol`
crate remains the authoritative spec; byte-for-byte agreement is enforced by shared
golden vectors in `tests/golden/protocol`.

## Consequences
- Two codec implementations must stay in lockstep (CI fails on any golden diff).
- BLE features cannot run on these boards; they are reported `unsupported` in
  capabilities and validated in simulation only.
- An ESP32 profile would reuse the same protocol and could use Rust; it is listed as
  unverified in `docs/hardware.md`.
