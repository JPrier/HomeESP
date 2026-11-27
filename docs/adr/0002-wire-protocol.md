# ADR 0002: Hand-specified TLV wire format

**Status:** accepted · 2026-11-26

Explicit framing (magic, schema version, kind, node id, boot id, sequence, monotonic
send time, config revision) followed by `type u8 | len u16 | payload` records. All
discriminants are explicit numbers, never Rust enum order. Unknown record types are
skipped and longer-than-known records keep their known prefix (additive evolution);
anything else bumps `SCHEMA_VERSION`. A hand-specified format was chosen over postcard
so the C++ firmware can implement it exactly without a serde port; it costs ~1 byte
per field more than varints, well within the 600 B/s budget.
