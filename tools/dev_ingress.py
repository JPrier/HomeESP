#!/usr/bin/env python3
"""Development-only LAN ingress relay.

Some development hosts (e.g. a Windows workstation without admin rights) block
inbound connections to new executables, so boards on the LAN cannot reach a
broker/server running there. This relay listens on the LAN and forwards to
loopback services:

  TCP  0.0.0.0:<mqtt_port>  -> 127.0.0.1:<mqtt_upstream>   (MQTT)
  UDP  0.0.0.0:<echo_port>  -> 127.0.0.1:<echo_upstream>   (UDP echo; per-client mapping)

It adds no authentication or data handling of its own: the broker still enforces
credentials/ACLs and the echo server still verifies HMACs. Production deployments
(deploy/compose.yaml) do not use it. Connection limits keep it from becoming an
amplifier or resource sink.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import selectors
import socket
import threading
import time

MAX_TCP_CONNS = 64
MAX_UDP_CLIENTS = 64
UDP_IDLE_S = 60
MAX_DATAGRAM = 512

log = logging.getLogger("ingress")


async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(4096):
            w.write(data)
            await w.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            w.close()
        except OSError:
            pass


class TcpRelay:
    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.active = 0

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        peer = w.get_extra_info("peername")
        if self.active >= MAX_TCP_CONNS:
            w.close()
            return
        self.active += 1
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.upstream_port), 5)
            log.info("tcp %s connected", peer[0] if peer else "?")
            await asyncio.gather(pipe(r, uw), pipe(ur, w))
        except (OSError, asyncio.TimeoutError) as e:
            log.warning("tcp upstream failed: %s", e)
            w.close()
        finally:
            self.active -= 1


def _no_connreset(sock: socket.socket) -> None:
    """Windows: stop ICMP port-unreachable from poisoning the UDP socket."""
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)  # type: ignore[attr-defined]
        except OSError:
            pass


def udp_relay(bind: str, port: int, upstream: int, stop: threading.Event) -> None:
    """Single-threaded selector relay with a bounded per-client upstream socket map.

    (asyncio datagram transports on the Windows proactor loop silently failed to send
    replies to LAN clients, so this uses plain non-blocking sockets.)"""
    sel = selectors.DefaultSelector()
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.bind((bind, port))
    front.setblocking(False)
    _no_connreset(front)
    sel.register(front, selectors.EVENT_READ, None)
    clients: dict[tuple, tuple[socket.socket, float]] = {}
    while not stop.is_set():
        for key, _ in sel.select(timeout=1.0):
            sock = key.fileobj
            try:
                data, addr = sock.recvfrom(MAX_DATAGRAM + 1)  # type: ignore[union-attr]
            except OSError:
                continue
            if len(data) > MAX_DATAGRAM:
                continue
            if key.data is None:  # from a LAN client -> upstream
                now = time.monotonic()
                for k in [k for k, (_, t) in clients.items() if now - t > UDP_IDLE_S]:
                    up, _ = clients.pop(k)
                    sel.unregister(up)
                    up.close()
                entry = clients.get(addr)
                if entry is None:
                    if len(clients) >= MAX_UDP_CLIENTS:
                        continue
                    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    up.connect(("127.0.0.1", upstream))
                    up.setblocking(False)
                    _no_connreset(up)
                    sel.register(up, selectors.EVENT_READ, addr)
                    entry = (up, now)
                clients[addr] = (entry[0], now)
                try:
                    entry[0].send(data)
                except OSError:
                    pass
            else:  # reply from upstream -> the LAN client it belongs to
                try:
                    front.sendto(data, key.data)
                except OSError as e:
                    log.debug("udp reply failed: %s", e)
    front.close()


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--mqtt-upstream", type=int, default=11883)
    ap.add_argument("--echo-port", type=int, default=47019)
    ap.add_argument("--echo-upstream", type=int, default=47020)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    tcp = TcpRelay(a.mqtt_upstream)
    server = await asyncio.start_server(tcp.handle, a.bind, a.mqtt_port)
    stop = threading.Event()
    threading.Thread(target=udp_relay, args=(a.bind, a.echo_port, a.echo_upstream, stop), daemon=True).start()
    log.info("relaying tcp %s:%d->%d udp %d->%d", a.bind, a.mqtt_port, a.mqtt_upstream, a.echo_port, a.echo_upstream)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
