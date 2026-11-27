# Operations guide and runbook

## Deploy

```sh
git clone https://github.com/JPrier/HomeESP.git src && cd src/deploy
cat > .env <<EOF
OBS_DIR=/srv/observatory        # config/, secrets/, data/, mosquitto/
OBS_UID=10101                   # a UID unused on this host
OBS_HEALTH_ADDR=192.0.2.10      # = server.bind address
OBS_HEALTH_PORT=18080
EOF
docker compose build server       # ~10 min on a 4-core desktop CPU
docker compose up -d broker server
```

`${OBS_DIR}` layout: `config/site.yaml`, `secrets/{api_tokens,mqtt_server,echo_keys}`
(0600, owned by `OBS_UID`), `data/` (SQLite), `mosquitto/{mosquitto.conf,acl,passwd,data/}`
(owned by 1883). Generate the broker `passwd` with the **broker image's own**
`mosquitto_passwd -U` (hashes from other mosquitto versions may be rejected — observed
with 2.1.x hashes on a 2.0.20 broker).

### Secrets

| File | Format |
|---|---|
| `api_tokens` | `operator=<≥24 chars>` and `viewer=<≥24 chars>` lines |
| `mqtt_server` | the server's broker password only |
| `echo_keys` | `node-01=<hex, ≥16 bytes>` per node (same key provisioned to the node) |
| node secrets (provisioning only, never on the server) | JSON: `common` (wifi_ssid, wifi_psk, site, mqtt_host, mqtt_port, echo_port) + `nodes.{id}` (mqtt_user, mqtt_pass, echo_key) |

Secrets are never passed on command lines, never logged, never returned by the API.

### Firewall

Keep everything LAN-only. Required inbound on the server host:

| Port | From | Purpose |
|---|---|---|
| TCP 1883 | node subnet | MQTT (per-node credentials + ACL) |
| UDP 47019 | node subnet | authenticated UDP echo |
| TCP 18080 (or `server.bind`) | management hosts | API + dashboard |

nftables example (insert **before** any terminal log/drop rule; do not reload a file
that starts with `flush ruleset` on a Docker host — it also flushes Docker's chains):

```sh
nft add rule inet filter input position <handle> ip saddr 192.0.2.0/24 tcp dport 1883 ct state new accept
nft add rule inet filter input position <handle> ip saddr 192.0.2.0/24 udp dport 47019 accept
nft add rule inet filter input position <handle> ip saddr <mgmt-ip> tcp dport 18080 ct state new accept
```
and persist the same lines in the boot-time ruleset.

## Nodes

```sh
python tools/esp.py list                                 # ports + MACs
python tools/esp.py flash --port COM5                    # writes app only; LittleFS secrets persist
python tools/esp.py provision --port COM5 --node node-01 --secrets nodes.json
python tools/esp.py monitor --port COM5 --seconds 20
```
Serial console commands (115200): `HO PING | SHOW | STATUS | SET <k> <v> | SAVE | REBOOT | FACTORY`.
Moving a node to a new broker: provision again with the new `mqtt_host`.

## Backups

`observatory-cli backup create --db data/observatory.sqlite --output backup-$(date +%F).sqlite`
(SQLite online backup API — safe while running; refuses to overwrite). Verify with
`observatory-cli backup verify --file …`. Restore: stop the server, replace
`data/observatory.sqlite` with the verified backup (owned by `OBS_UID`), start. Back up
`config/`, `secrets/` and `mosquitto/passwd` separately and encrypted.

## Runbook

| Symptom | Evidence to inspect | Safe checks / remediation | Verify |
|---|---|---|---|
| Node missing | `/api/v1/nodes/{id}` lifecycle events, broker log `as ho-node-…` | power/USB; `esp.py monitor`; `HO STATUS` (wifi/mqtt state) | node `online`, incident resolves |
| Broker auth failure | broker log `not authorised` | regenerate `passwd` with the broker image's `mosquitto_passwd`; check ACL username = node id | `New client connected … u'node-01'` |
| MQTT reconnect loop on nodes | `mqtt_disconnected` reason codes (65527 = lwmqtt −9) | ensure firmware ≥ 0.1.1 (QoS 0 publishes, ack-first subscribe) | no reconnects in lifecycle |
| Clock drift / bad event times | `batches.clock_uncertainty_ms`, ingest lag | uncertainty grows with transit jitter; reboot resets per-boot estimate | lag < 3 s |
| AP scan disrupting probes | probes with `scan_overlap`, skipped probes with error 12 | lengthen `neighbor_scan_ms` or set `passive_scan_enabled: false` | overlap counts flat |
| Phone advertisements absent | device `not_observed` | ESP8266 has no BLE: needs BLE-capable nodes | — |
| DNS false positives | DNS matrix; `dns_bad` vs `eligible` | check expected answer in config; wildcard domains break NXDOMAIN expectations | matrix healthy |
| Loss alarms on noisy Wi‑Fi | target reason shows loss + lower bound | thresholds in `thresholds.*`; see ADR 0004 | — |
| SNMP counter reset | rate reported `Reset`, not a spike | none needed | — |
| OPNsense API unavailable | adapter returns `Forbidden` / `NotAvailable` | least-privilege key with read access to the named endpoints | data shows, not unknown |
| Storage pressure | `/metrics` `ho_db_bytes`, log "above 90% of budget" | retention trims raw data; raise `retention.max_db_mb` or shorten `raw_days` | size stable |
| HA stale state | availability topics `offline` | HA restart republishes discovery on `homeassistant/status online` | entities available |
| Notification not delivered | `/api/v1/outbox` status/attempts/last_error | fix endpoint/token; transient errors retry with backoff up to 12 attempts | status `sent` |
| Healthcheck unhealthy | `docker compose ps` | `OBS_HEALTH_ADDR/PORT` must match `server.bind` | `healthy` |
| OTA rollback | — | OTA not supported on ESP8266 profile; reflash over USB | `fw_version` in capabilities |
