"""Unit tests for host tooling (no hardware required)."""
import importlib.util
import pathlib
import socket
import sys
import threading
import time

import pytest

TOOLS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_provision_lines_order_and_validation():
    esp = load("esp")
    node = {"wifi_ssid": "Home Net", "wifi_psk": "pw", "site": "home", "mqtt_host": "192.0.2.10", "mqtt_port": 1883,
            "mqtt_user": "node-01", "mqtt_pass": "secret", "echo_key": "00" * 32, "echo_port": 47019}
    lines = esp.provision_lines(node, "node-01")
    assert [k for k, _ in lines] == esp.KEY_ORDER
    assert dict(lines)["node_id"] == "node-01"
    with pytest.raises(ValueError):
        esp.provision_lines({**node, "mqtt_pass": "has space"}, "node-01")
    with pytest.raises(ValueError):
        esp.provision_lines({k: v for k, v in node.items() if k != "wifi_psk"}, "node-01")


def test_secret_keys_are_redacted_set():
    esp = load("esp")
    assert {"wifi_psk", "mqtt_pass", "echo_key"} <= esp.SECRET_KEYS


def test_size_gate(tmp_path):
    sg = load("size_gate")
    f = tmp_path / "s.txt"
    f.write_text("RAM:   [======    ]  57.3% (used 1 bytes)\nFlash: [===       ]  32.6% (used 1 bytes)\n")
    sys.argv = ["x", str(f), "70", "60"]
    assert sg.main() == 0
    sys.argv = ["x", str(f), "50", "60"]
    assert sg.main() == 1


def test_udp_relay_roundtrip():
    ing = load("dev_ingress")
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.bind(("127.0.0.1", 0))
    up_port = up.getsockname()[1]
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    front_port = probe.getsockname()[1]
    probe.close()
    stop = threading.Event()
    t = threading.Thread(target=ing.udp_relay, args=("127.0.0.1", front_port, up_port, stop), daemon=True)
    t.start()
    time.sleep(0.2)

    def echo():
        data, addr = up.recvfrom(600)
        up.sendto(data.upper(), addr)

    threading.Thread(target=echo, daemon=True).start()
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2)
    c.sendto(b"hello", ("127.0.0.1", front_port))
    assert c.recvfrom(100)[0] == b"HELLO"
    # Oversized datagrams are dropped, never forwarded.
    c.sendto(b"x" * 1000, ("127.0.0.1", front_port))
    c.settimeout(0.5)
    with pytest.raises(socket.timeout):
        c.recvfrom(2000)
    stop.set()
