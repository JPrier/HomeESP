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


class UdpClient(asyncio.DatagramProtocol):
    def __init__(self, relay: "UdpRelay", addr: tuple) -> None:
        self.relay, self.addr, self.transport, self.last = relay, addr, None, time.monotonic()

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, _addr) -> None:  # type: ignore[override]
        # Responses are never larger than requests at the echo server; still cap here.
        if self.relay.transport and len(data) <= MAX_DATAGRAM:
            self.relay.transport.sendto(data, self.addr)


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.clients: dict[tuple, UdpClient] = {}
        self.transport = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if len(data) > MAX_DATAGRAM:
            return
        asyncio.get_running_loop().create_task(self.forward(data, addr))

    async def forward(self, data: bytes, addr: tuple) -> None:
        now = time.monotonic()
        for k in [k for k, c in self.clients.items() if now - c.last > UDP_IDLE_S]:
            self.clients.pop(k).transport.close()
        c = self.clients.get(addr)
        if c is None:
            if len(self.clients) >= MAX_UDP_CLIENTS:
                return
            loop = asyncio.get_running_loop()
            _, c = await loop.create_datagram_endpoint(lambda: UdpClient(self, addr),
                                                       remote_addr=("127.0.0.1", self.upstream_port))
            self.clients[addr] = c
        c.last = now
        c.transport.sendto(data)


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
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: UdpRelay(a.echo_upstream), local_addr=(a.bind, a.echo_port))
    log.info("relaying tcp %s:%d->%d udp %d->%d", a.bind, a.mqtt_port, a.mqtt_upstream, a.echo_port, a.echo_upstream)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
