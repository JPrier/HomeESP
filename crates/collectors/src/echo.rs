//! Authenticated UDP echo responder (spec §11.1).
//!
//! Request: `"HE" | 1 | node_len | node_id | seq u32 | nonce u32 | mono u32 | mac[16]`
//! where mac = HMAC-SHA256(node key, everything before it)[..16]. The response has the
//! same size and layout with magic "HR" and a fresh MAC, so it can never amplify.
//! Unknown nodes, bad MACs, replays and over-budget senders get no reply at all.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

pub const MAC_LEN: usize = 16;
pub const MAX_REQUEST: usize = 4 + 32 + 12 + MAC_LEN;

type HmacSha256 = Hmac<Sha256>;

fn mac(key: &[u8], body: &[u8]) -> Option<[u8; MAC_LEN]> {
    let mut m = HmacSha256::new_from_slice(key).ok()?;
    m.update(body);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(full.get(..MAC_LEN)?);
    Some(out)
}

/// Build a request or response (also used by tests and the simulator).
pub fn build(response: bool, node: &str, seq: u32, nonce: u32, mono: u32, key: &[u8]) -> Option<Vec<u8>> {
    let n = node.len();
    if n == 0 || n > 32 {
        return None;
    }
    let mut v = Vec::with_capacity(4 + n + 12 + MAC_LEN);
    v.extend_from_slice(if response { b"HR" } else { b"HE" });
    v.push(1);
    v.push(u8::try_from(n).ok()?);
    v.extend_from_slice(node.as_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&nonce.to_le_bytes());
    v.extend_from_slice(&mono.to_le_bytes());
    let m = mac(key, &v)?;
    v.extend_from_slice(&m);
    Some(v)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Size,
    Format,
    UnknownNode,
    BadMac,
    Replay,
    RateLimited,
}

impl Reject {
    pub fn label(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Format => "format",
            Self::UnknownNode => "unknown_node",
            Self::BadMac => "bad_mac",
            Self::Replay => "replay",
            Self::RateLimited => "rate_limited",
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Stateful verifier: keys, replay window and per-node token buckets.
pub struct EchoResponder {
    keys: HashMap<String, Vec<u8>>,
    recent: HashMap<String, VecDeque<(u32, u32)>>,
    buckets: HashMap<String, Bucket>,
    rate_per_s: f64,
    burst: f64,
    pub served: u64,
    pub rejected: HashMap<&'static str, u64>,
}

impl EchoResponder {
    pub fn new(keys: HashMap<String, Vec<u8>>, rate_per_s: f64, burst: f64) -> Self {
        Self { keys, recent: HashMap::new(), buckets: HashMap::new(), rate_per_s, burst, served: 0, rejected: HashMap::new() }
    }

    /// Validate a request and produce the response bytes (same length) or a rejection.
    pub fn handle(&mut self, req: &[u8], now: Instant) -> Result<Vec<u8>, Reject> {
        let r = self.handle_inner(req, now);
        match &r {
            Ok(_) => self.served += 1,
            Err(e) => *self.rejected.entry(e.label()).or_default() += 1,
        }
        r
    }

    fn handle_inner(&mut self, req: &[u8], now: Instant) -> Result<Vec<u8>, Reject> {
        if req.len() < 4 + 1 + 12 + MAC_LEN || req.len() > MAX_REQUEST {
            return Err(Reject::Size);
        }
        if req.get(..3) != Some(b"HE\x01".as_slice()) {
            return Err(Reject::Format);
        }
        let n = usize::from(*req.get(3).ok_or(Reject::Format)?);
        if req.len() != 4 + n + 12 + MAC_LEN {
            return Err(Reject::Format);
        }
        let node = std::str::from_utf8(req.get(4..4 + n).ok_or(Reject::Format)?).map_err(|_| Reject::Format)?;
        let key = self.keys.get(node).ok_or(Reject::UnknownNode)?;
        let body = req.get(..4 + n + 12).ok_or(Reject::Format)?;
        let got = req.get(4 + n + 12..).ok_or(Reject::Format)?;
        let want = mac(key, body).ok_or(Reject::BadMac)?;
        // Constant-time compare.
        if got.len() != MAC_LEN || got.iter().zip(want.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
            return Err(Reject::BadMac);
        }
        let rd = |at: usize| -> Result<u32, Reject> {
            let b = req.get(at..at + 4).ok_or(Reject::Format)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let (seq, nonce, mono) = (rd(4 + n)?, rd(8 + n)?, rd(12 + n)?);
        let node = node.to_string();
        // Rate limit per authenticated node.
        let b = self.buckets.entry(node.clone()).or_insert(Bucket { tokens: self.burst, last: now });
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * self.rate_per_s).min(self.burst);
        b.last = now;
        if b.tokens < 1.0 {
            return Err(Reject::RateLimited);
        }
        b.tokens -= 1.0;
        // Replay window (bounded per node).
        let seen = self.recent.entry(node.clone()).or_default();
        if seen.contains(&(seq, nonce)) {
            return Err(Reject::Replay);
        }
        if seen.len() >= 64 {
            seen.pop_front();
        }
        seen.push_back((seq, nonce));
        let key = self.keys.get(&node).ok_or(Reject::UnknownNode)?;
        build(true, &node, seq, nonce, mono, key).ok_or(Reject::Format)
    }
}

/// Run the responder on a bound socket until cancelled.
pub async fn serve(sock: tokio::net::UdpSocket, mut r: EchoResponder, stats: std::sync::Arc<std::sync::Mutex<(u64, u64)>>) {
    let mut buf = [0u8; 512];
    loop {
        let (n, from): (usize, SocketAddr) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "echo recv failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let req = buf.get(..n).unwrap_or(&[]);
        match r.handle(req, Instant::now()) {
            Ok(resp) => {
                debug_assert!(resp.len() <= req.len());
                if let Err(e) = sock.send_to(&resp, from).await {
                    tracing::debug!(error = %e, "echo send failed");
                }
            }
            Err(e) => tracing::debug!(reason = e.label(), "echo request rejected"),
        }
        if let Ok(mut s) = stats.lock() {
            *s = (r.served, r.rejected.values().sum());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-echo-key-0123456789abcdef!!";

    #[test]
    fn matches_firmware_golden_vector() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/protocol/udp_echo_request.hex");
        let want = std::fs::read_to_string(path).unwrap();
        let got = build(false, "node-01", 7, 0xdead_beef, 123_456, KEY).unwrap();
        assert_eq!(hex::encode(got), want.trim(), "Rust and C++ echo encodings must agree");
    }

    #[test]
    fn verifies_and_never_amplifies() {
        let mut r = EchoResponder::new([("node-01".to_string(), KEY.to_vec())].into(), 10.0, 5.0);
        let now = Instant::now();
        let req = build(false, "node-01", 1, 42, 0, KEY).unwrap();
        let resp = r.handle(&req, now).unwrap();
        assert_eq!(resp.len(), req.len());
        assert_eq!(&resp[..2], b"HR");
        assert_eq!(r.handle(&req, now), Err(Reject::Replay));
        let mut tampered = build(false, "node-01", 2, 1, 0, KEY).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(r.handle(&tampered, now), Err(Reject::BadMac));
        let other = build(false, "node-99", 1, 1, 0, KEY).unwrap();
        assert_eq!(r.handle(&other, now), Err(Reject::UnknownNode));
        assert_eq!(r.handle(&[0u8; 400], now), Err(Reject::Size));
        let wrong_key = build(false, "node-01", 3, 3, 0, b"another-key").unwrap();
        assert_eq!(r.handle(&wrong_key, now), Err(Reject::BadMac));
    }

    #[test]
    fn rate_limits_per_node() {
        let mut r = EchoResponder::new([("n".to_string(), KEY.to_vec())].into(), 1.0, 3.0);
        let now = Instant::now();
        let ok = (0..10).filter(|i| r.handle(&build(false, "n", *i, *i, 0, KEY).unwrap(), now).is_ok()).count();
        assert_eq!(ok, 3);
    }
}
