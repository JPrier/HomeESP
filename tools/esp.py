#!/usr/bin/env python3
"""Board tooling for Home Observatory ESP8266 nodes.

  python tools/esp.py list                          # ports + chip MACs
  python tools/esp.py flash --port COM5 [--bin firmware/.pio/build/esp8266-4m/firmware.bin]
  python tools/esp.py monitor --port COM5 --seconds 20 [--reset]
  python tools/esp.py provision --port COM5 --node node-01 --secrets local/secrets/nodes.json

Boards are identified by MAC (COM numbers move when USB re-enumerates). Secrets are
read from a JSON file and sent over the serial console; they are never printed or
passed on the command line. See docs/provisioning.md for the file format.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ch340_shim  # noqa: E402,F401  (patches pyserial on Windows)
import serial  # noqa: E402
from serial.tools import list_ports  # noqa: E402

ROOT = HERE.parent
DEFAULT_BIN = ROOT / "firmware" / ".pio" / "build" / "esp8266-4m" / "firmware.bin"
SECRET_KEYS = {"wifi_psk", "mqtt_pass", "echo_key"}
KEY_ORDER = ["wifi_ssid", "wifi_psk", "node_id", "site", "mqtt_host", "mqtt_port", "mqtt_user",
             "mqtt_pass", "echo_key", "echo_port"]


def esptool(*args: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(HERE / "ch340_shim.py"), "esptool", *args]
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace")


def chip_mac(port: str) -> str | None:
    r = esptool("--port", port, "--baud", "115200", "read-mac")
    m = re.search(r"MAC:\s+([0-9a-f:]{17})", r.stdout)
    return m.group(1) if m else None


def cmd_list(_: argparse.Namespace) -> int:
    for p in list_ports.comports():
        if p.vid is None:
            continue
        mac = chip_mac(p.device)
        print(f"{p.device}\tvid={p.vid:04x} pid={p.pid:04x}\tmac={mac or '?'}")
    return 0


def cmd_flash(a: argparse.Namespace) -> int:
    binp = Path(a.bin)
    if not binp.exists():
        print(f"firmware not built: {binp}", file=sys.stderr)
        return 2
    r = esptool("--port", a.port, "--baud", "460800", "write-flash", "0x0", str(binp))
    tail = [ln for ln in r.stdout.splitlines() if re.search(r"Wrote|Hash|MAC|rror", ln)]
    print("\n".join(tail))
    return 0 if "Hash of data verified" in r.stdout else 1


def open_console(port: str, reset: bool) -> serial.Serial:
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = port, 115200, 0.2
    s.dtr = False
    s.rts = False
    s.open()
    if reset:
        s.rts = True
        time.sleep(0.1)
        s.rts = False
    return s


def printable(b: bytes) -> str:
    return re.sub(r"[^\x09\x0a\x20-\x7e]", "", b.decode("latin1"))


def cmd_monitor(a: argparse.Namespace) -> int:
    s = open_console(a.port, a.reset)
    end = time.time() + a.seconds
    buf = b""
    while time.time() < end:
        buf += s.read(512)
    s.close()
    sys.stdout.write(printable(buf))
    return 0


def send(s: serial.Serial, line: str, expect: str = "HO ", timeout: float = 3.0) -> str:
    s.reset_input_buffer()
    s.write((line + "\n").encode())
    s.flush()
    end = time.time() + timeout
    acc = b""
    while time.time() < end:
        acc += s.read(256)
        for ln in printable(acc).splitlines():
            if ln.startswith(expect):
                return ln
    return ""


def provision_lines(node: dict, node_id: str) -> list[tuple[str, str]]:
    vals = dict(node)
    vals["node_id"] = node_id
    missing = [k for k in KEY_ORDER if k not in vals or vals[k] in ("", None)]
    if missing:
        raise ValueError(f"secrets file missing keys for {node_id}: {missing}")
    out = []
    for k in KEY_ORDER:
        v = str(vals[k])
        if any(c.isspace() for c in v) and k != "wifi_ssid":
            raise ValueError(f"{k} must not contain whitespace")
        out.append((k, v))
    return out


def cmd_provision(a: argparse.Namespace) -> int:
    data = json.loads(Path(a.secrets).read_text())
    common = data.get("common", {})
    node = {**common, **data.get("nodes", {}).get(a.node, {})}
    lines = provision_lines(node, a.node)
    s = open_console(a.port, reset=True)
    time.sleep(1.5)
    pong = send(s, "HO PING", "HO OK PONG")
    if not pong:
        print("no response to HO PING (is the Home Observatory firmware flashed?)", file=sys.stderr)
        return 1
    print(pong)
    for k, v in lines:
        resp = send(s, f"HO SET {k} {v}")
        shown = "<redacted>" if k in SECRET_KEYS else v
        print(f"set {k}={shown}: {resp or 'NO RESPONSE'}")
        if not resp.startswith("HO OK"):
            return 1
    resp = send(s, "HO SAVE")
    print(resp)
    if not resp.startswith("HO OK SAVED"):
        return 1
    print(send(s, "HO SHOW"))
    send(s, "HO REBOOT")
    s.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    f = sub.add_parser("flash")
    f.add_argument("--port", required=True)
    f.add_argument("--bin", default=str(DEFAULT_BIN))
    f.set_defaults(fn=cmd_flash)
    m = sub.add_parser("monitor")
    m.add_argument("--port", required=True)
    m.add_argument("--seconds", type=float, default=15)
    m.add_argument("--reset", action="store_true")
    m.set_defaults(fn=cmd_monitor)
    p = sub.add_parser("provision")
    p.add_argument("--port", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--secrets", required=True, help="JSON file; never committed")
    p.set_defaults(fn=cmd_provision)
    a = ap.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except AttributeError:
            pass
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
