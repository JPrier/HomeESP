# Hardware matrix

## Verified target

| Item | Value |
|---|---|
| Chip | **ESP8266EX**, 160 MHz capable, crystal 26 MHz (read via esptool on all 3 boards) |
| Flash | 4 MB (manufacturer 0x5e, device 0x4016) |
| Board | NodeMCU-style dev board, CH340 USB-UART, USB powered |
| Radio | 2.4 GHz 802.11b/g/n only. **No Bluetooth.** No 5 GHz. No CSI/FTM in this build |
| Shipped firmware before us | Espressif AT firmware, NONOS SDK 2.0.0 (full 4 MB backups kept locally) |
| Toolchain | PlatformIO 6, `espressif8266@4.2.1`, Arduino core 3.1.2, lwIP2 low-memory, C++17 |
| Firmware size | flash 33% (344 KB of 1 MB app slot), static RAM 57% (46.9 KB of 80 KB) |
| Partition | `eagle.flash.4m1m.ld`: 1 MB app + 1 MB LittleFS (credentials + last-known-good config) |

| Capability | Status |
|---|---|
| Wi‑Fi STA, events, BSSID/channel/RSSI | **verified on hardware** |
| Passive AP scan (120 ms dwell) | **verified on hardware** (radio-coordinated with probes) |
| ICMP (lwIP raw PCB), DNS (answer-checked), authenticated UDP echo, TCP connect | **verified on hardware** |
| Desired config (revisioned, validated, staged atomically, reported) | **verified on hardware** |
| Durable event ACK round trip | **verified on hardware** |
| BLE observer | **unsupported** (no radio); reported in capabilities |
| TLS MQTT | not in 0.1.x firmware (BearSSL fits; not yet implemented) — plaintext on LAN with per-node credentials, firewall-scoped |
| OTA A/B | not implemented; USB update via `tools/esp.py flash` (reports `ota=false`) |
| Flash encryption / secure boot | **not available on ESP8266** — physical access exposes stored credentials |

## Unverified profiles

ESP32 (classic/C3/S3) would be the target for BLE presence. The protocol is shared and
`ho-protocol` is `no_std`, but no ESP32 firmware has been built or tested here.

## Windows + clone CH340 (driver 3.9.2024.9)

The boards use clone CH340 chips. With WCH's Windows driver 3.9.2024.9,
`SetCommState` fails with `ERROR_GEN_FAILURE (31)` unless the baud rate *changes* and
one side of the change is 9600; re-applying identical settings also fails. pyserial
re-applies the full line state on every timeout change, so stock esptool cannot even
open the port. `tools/ch340_shim.py` patches pyserial to (a) skip `SetCommState` when
only timeouts change and (b) hop through 9600 when a direct change is refused. With it,
esptool reads and writes flash at 460800 baud. Linux's `ch341` driver does not have
this problem. COM port numbers move on re-enumeration — tools identify boards by MAC.

## Field measurements (live, 3 nodes, one 2.4 GHz AP, channel 1 shared with ~30 networks)

| Metric | Observed |
|---|---|
| Node RSSI | −65 to −71 dBm |
| Gateway ICMP RTT (wireless) | median 6–15 ms, p95 13–45 ms |
| Wired central baseline to gateway | median 0.44 ms |
| Probe timeouts (1 s) | 0–16% per target per 5 min; only 4 of 104 overlapped a scan; independent PC→node ping lost 1/40 |
| App payload per node | ~100 B telemetry frame every 2 s (~50–60 B/s incl. probes/health) |
| Modem sleep | disabled (`WIFI_NONE_SLEEP`) to avoid DTIM-inflated RTTs on USB power |
