# ADR 0006: Compose with host networking behind the host firewall

**Status:** accepted · 2026-11-26

Broker and server run as read-only, `cap_drop: ALL`, memory-limited containers with
`network_mode: host`, binding explicitly to the LAN address and loopback. Host
networking keeps exposure governed by the host's own nftables `input` chain (narrow,
LAN-only rules) instead of Docker's FORWARD/NAT rules, and lets the server use
unprivileged ICMP ping sockets. The service runs under a dedicated UID that must not
collide with other host users (configurable as `OBS_UID`).
