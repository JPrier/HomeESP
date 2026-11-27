#!/usr/bin/env python3
"""Print a compact live status from a running observatory-server.
usage: python tools/status.py [base_url] [tokens_file]"""
import json
import sys
import urllib.request

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
tokfile = sys.argv[2] if len(sys.argv) > 2 else "local/secrets/api_tokens"
with open(tokfile) as fh:
    token = [ln.split("=", 1)[1].strip() for ln in fh if ln.startswith("viewer=")][0]
req = urllib.request.Request(base + "/api/v1/site/status", headers={"Authorization": "Bearer " + token})
d = json.load(urllib.request.urlopen(req, timeout=10))
print("ingestion", d["ingestion_ok"], "mqtt", d["mqtt_connected"], "desired_rev", d["desired_revision"], "uptime_s", d["uptime_s"])
for n in d["nodes"]:
    print(f"  node {n['id']:8s} {n['liveness']:8s} rssi={n['rssi_dbm']}")
for t in d["targets"]:
    s = t["stats"]
    print(f"  {t['vantage']:8s} {t['target']:13s} {t['health']:10s} n={s['samples']:4d} p50={s['p50_ms']} p95={s['p95_ms']} loss={s['loss_pct']} | {t['reason']}")
print("active incidents:", [(i["id"], i["hypothesis"]["title"]) for i in d["active_incidents"]])
print("score:", d["score"]["value"], "coverage", d["score"]["coverage"])
print("ingest:", json.dumps(d["ingest"]))
print("storage:", json.dumps(d["storage"]))
