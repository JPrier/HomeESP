//! Home Observatory wire protocol, schema version 1.
//!
//! The authoritative description lives in `docs/protocol.md`. In short, a frame is
//!
//! ```text
//! magic "HO" | schema u16 | kind u8 | flags u8 | node_id_len u8 | node_id
//! | boot_id [16] | sequence u64 | sent_mono_ms u64 | config_revision u64
//! | record_count u8 | records...
//! record = type u8 | len u16 | payload[len]
//! ```
//!
//! All integers are little-endian. Discriminants are explicit and never derived
//! from Rust enum order. Decoding is total: every input either yields a frame or a
//! [`DecodeError`]; nothing panics and nothing allocates. Unknown record types are
//! skipped and records longer than this version expects keep their known prefix,
//! which is the additive-compatibility rule. Anything else bumps `SCHEMA_VERSION`.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::indexing_slicing, clippy::cast_possible_truncation)]

mod codec;
mod records;

pub use codec::{decode_frame, DecodeError, EncodeError, Frame, FrameWriter, RecordIter};
pub use records::*;

/// Two magic bytes at the start of every frame.
pub const MAGIC: [u8; 2] = *b"HO";
/// The only schema version this crate encodes and decodes.
pub const SCHEMA_VERSION: u16 = 1;
/// Hard cap on an encoded frame (also the MQTT payload cap for telemetry).
pub const MAX_FRAME_BYTES: usize = 1024;
/// Longest node id in bytes.
pub const MAX_NODE_ID: usize = 32;
/// Longest short identifier (probe target id, BLE device id, sensor id).
pub const MAX_SHORT_ID: usize = 24;
/// Longest firmware/profile/chip string.
pub const MAX_LABEL: usize = 24;
/// Longest DNS query name carried in a probe target.
pub const MAX_QNAME: usize = 63;
/// Maximum AP entries in one scan record.
pub const MAX_AP_ENTRIES: usize = 32;
/// Fixed frame header size excluding the variable node id.
pub const HEADER_FIXED_BYTES: usize = 2 + 2 + 1 + 1 + 1 + 16 + 8 + 8 + 8 + 1;

/// Frame kinds. Values are part of the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgKind {
    /// Disposable periodic observations (QoS 0).
    Telemetry = 1,
    /// Critical lifecycle events; server acknowledges after durable commit.
    Events = 2,
    /// Birth / last-will / heartbeat status (retained).
    Status = 3,
    /// Capability report (retained).
    Capabilities = 4,
    /// Node's applied/rejected configuration revision (retained).
    ConfigReported = 5,
    /// Server -> node desired configuration (retained, revisioned).
    ConfigDesired = 16,
    /// Server -> node durable acknowledgement of an events frame.
    Ack = 17,
}

impl MsgKind {
    /// Map a wire byte to a kind.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Telemetry,
            2 => Self::Events,
            3 => Self::Status,
            4 => Self::Capabilities,
            5 => Self::ConfigReported,
            16 => Self::ConfigDesired,
            17 => Self::Ack,
            _ => return None,
        })
    }
}

/// Frame flag bits.
pub mod flags {
    /// The sender wants an application-level ACK after durable storage.
    pub const NEEDS_ACK: u8 = 0b0000_0001;
    /// This frame is a fragment of a larger logical batch (more follow).
    pub const MORE_FRAGMENTS: u8 = 0b0000_0010;
    /// Data in this frame was buffered while offline (replayed history).
    pub const REPLAYED: u8 = 0b0000_0100;
}

/// Frame header, shared by every kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub kind: MsgKind,
    pub flags: u8,
    pub node_id: &'a str,
    pub boot_id: [u8; 16],
    pub sequence: u64,
    pub sent_mono_ms: u64,
    pub config_revision: u64,
}

/// Validate a node id: 1..=32 bytes of `[a-z0-9-]`, not starting or ending with '-'.
pub fn valid_node_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.is_empty() || b.len() > MAX_NODE_ID {
        return false;
    }
    if b.first() == Some(&b'-') || b.last() == Some(&b'-') {
        return false;
    }
    b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Validate a short identifier / label: printable ASCII without spaces or quotes.
pub fn valid_short(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b.iter().all(|c| c.is_ascii_graphic() && *c != b'"' && *c != b'\\')
}

/// Validate a DNS query name (LDH labels separated by dots, <= 63 bytes total here).
pub fn valid_qname(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > MAX_QNAME {
        return false;
    }
    s.split('.').all(|label| {
        let l = label.as_bytes();
        !l.is_empty()
            && l.len() <= 63
            && l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
            && l.first() != Some(&b'-')
            && l.last() != Some(&b'-')
    })
}
