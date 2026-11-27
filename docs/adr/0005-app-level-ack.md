# ADR 0005: Application-level durable ACK; node publishes at QoS 0

**Status:** accepted · 2026-11-26

QoS 1 at the broker does not prove persistence, so critical event frames carry
`NEEDS_ACK` and the server publishes an ACK only after the frame is committed. The node
keeps the frame and re-sends it every 5 s (bounded) until ACKed.

Field finding: the ESP8266 MQTT library (lwmqtt) aborts the session with
`MISSING_OR_WRONG_PACKET` (-9) when an unrelated packet (e.g. the retained desired
config or an ACK) arrives while it blocks for a PUBACK/SUBACK. Since durability is
already end-to-end, nodes publish at QoS 0 and subscribe to `ack` before the retained
`config/desired`. After the change, observed reconnects dropped from repeated -9
disconnects to none outside deliberate restarts.
