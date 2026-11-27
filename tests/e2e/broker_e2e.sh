#!/usr/bin/env bash
# End-to-end test against a REAL mosquitto broker with per-node credentials + ACLs:
#   golden telemetry frame -> broker -> server -> SQLite -> API
#   critical events frame  -> durable insert -> application ACK back to the node
#   cross-node publish     -> refused by broker ACL (never reaches the server)
# Requires: mosquitto, mosquitto_pub/sub, python3, built target/debug binaries.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${BIN_DIR:-$root/target/debug}"
work="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
port=18831; api=18081
node_pw="node-01-e2e-password-$RANDOM"
srv_pw="server-e2e-password-$RANDOM"
op="e2e-operator-token-0000000000000000"
view="e2e-viewer-token-00000000000000000000"

mkdir -p "$work/secrets" "$work/mosq"
printf 'node-01:%s\nnode-02:x-%s\nobservatory-server:%s\n' "$node_pw" "$node_pw" "$srv_pw" > "$work/mosq/passwd"
mosquitto_passwd -U "$work/mosq/passwd"
chmod 0600 "$work/mosq/passwd"
cp "$root/deploy/mosquitto/acl" "$work/mosq/acl"
cat > "$work/mosq/mosquitto.conf" <<EOF
listener $port 127.0.0.1
allow_anonymous false
password_file $work/mosq/passwd
acl_file $work/mosq/acl
EOF
mosquitto -c "$work/mosq/mosquitto.conf" > "$work/mosq.log" 2>&1 &
printf '%s' "$srv_pw" > "$work/secrets/mqtt_server"
printf 'operator=%s\nviewer=%s\n' "$op" "$view" > "$work/secrets/api_tokens"
sed -e "s#bind: 0.0.0.0:8080#bind: 127.0.0.1:$api#" \
    -e "s#database_path: /data/observatory.sqlite#database_path: $work/db.sqlite#" \
    -e "s#echo_bind: 0.0.0.0:47019#echo_bind: 127.0.0.1:47119#" \
    -e "s#api_tokens_file: /run/secrets/api_tokens#api_tokens_file: $work/secrets/api_tokens#" \
    -e "/echo_keys_file/d" \
    -e "s#host: broker#host: 127.0.0.1#" -e "s#port: 1883#port: $port#" \
    -e "s#password_file: /run/secrets/mqtt_server#password_file: $work/secrets/mqtt_server#" \
    -e '/^central_checks:/,/^devices:/{/^devices:/!d}' \
    "$root/configs/sim-site.yaml" > "$work/site.yaml"
"$bin/observatory-cli" config validate --file "$work/site.yaml"
"$bin/observatory-server" --config "$work/site.yaml" > "$work/server.log" 2>&1 &

for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$api/health/ready" >/dev/null && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$api/health/ready" || { cat "$work/server.log"; exit 1; }

hex2bin() { python3 -c "import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(open(sys.argv[1]).read().strip()))" "$1"; }
hex2bin "$root/tests/golden/protocol/telemetry_basic.hex" > "$work/telemetry.bin"
hex2bin "$root/tests/golden/protocol/events_lifecycle.hex" > "$work/events.bin"
T=observatory/v1/home/nodes

# Listen for the durable ACK as node-01.
mosquitto_sub -h 127.0.0.1 -p $port -u node-01 -P "$node_pw" -t "$T/node-01/ack" -C 1 -W 10 -F '%l' > "$work/ack.txt" &
sub=$!
sleep 0.5
mosquitto_pub -h 127.0.0.1 -p $port -u node-01 -P "$node_pw" -t "$T/node-01/telemetry" -f "$work/telemetry.bin"
mosquitto_pub -h 127.0.0.1 -p $port -u node-01 -P "$node_pw" -t "$T/node-01/telemetry" -f "$work/telemetry.bin"   # duplicate
mosquitto_pub -h 127.0.0.1 -p $port -u node-01 -P "$node_pw" -q 1 -t "$T/node-01/events" -f "$work/events.bin"
# ACL: node-01 may not publish as node-02 (broker drops it) nor publish desired config.
mosquitto_pub -h 127.0.0.1 -p $port -u node-01 -P "$node_pw" -t "$T/node-02/telemetry" -f "$work/telemetry.bin" || true
mosquitto_pub -h 127.0.0.1 -p $port -u node-01 -P "$node_pw" -t "$T/node-01/config/desired" -m x || true
# Bad credentials are refused outright.
if mosquitto_pub -h 127.0.0.1 -p $port -u node-01 -P wrong -t "$T/node-01/telemetry" -m x 2>/dev/null; then
  echo "FAIL: bad password accepted"; exit 1
fi
wait $sub || { echo "FAIL: no ACK received"; cat "$work/server.log"; exit 1; }
[[ -s "$work/ack.txt" ]] || { echo "FAIL: empty ACK"; exit 1; }
sleep 1

status=$(curl -sf -H "Authorization: Bearer $view" "http://127.0.0.1:$api/api/v1/site/status")
python3 - "$status" <<'EOF'
import json, sys
s = json.loads(sys.argv[1])
ing, st = s["ingest"], s["storage"]
print("ingest:", ing, "storage:", st)
assert ing["frames_accepted"] == 2, "telemetry + events accepted"
assert ing["frames_duplicate"] == 1, "duplicate detected"
assert st["batches"] == 2 and st["lifecycle_events"] == 2, st
assert st["probe_results"] == 2, "no cross-node frame reached storage"
print("E2E OK")
EOF
grep -q "Denied PUBLISH" "$work/mosq.log" || true
echo "broker ACL denials:"; grep -c "denied\|Denied" "$work/mosq.log" || true
