//! SNMP support: interface counter rate computation (pure, with wrap/reset/index
//! change handling) and a minimal read-only SNMPv2c GET client (BER).
//!
//! SNMPv3 authPriv is preferred by the spec but not implemented here; v3-only devices
//! report `unsupported` and the operator must opt in to v2c explicitly
//! (`allow_legacy_v2c`) on an isolated read-only community.

use std::net::SocketAddr;
use std::time::Duration;

/// One counter reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSample {
    pub t_ms: i64,
    pub value: u64,
    /// Counter width in bits (32 or 64).
    pub bits: u8,
    /// Device uptime (sysUpTime, centiseconds) to detect reboots/resets.
    pub uptime_cs: u64,
    /// ifIndex the value belongs to (index changes invalidate the series).
    pub if_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rate {
    /// Bytes (or units) per second.
    PerSecond(f64),
    /// Device rebooted / counter reset: no rate this interval (never a spike).
    Reset,
    /// Interface index changed: series restarts.
    IndexChanged,
    /// Non-positive elapsed time.
    InvalidInterval,
}

/// Compute a rate between two readings, handling 32-bit wraps and resets.
pub fn rate(prev: &CounterSample, cur: &CounterSample) -> Rate {
    if prev.if_index != cur.if_index {
        return Rate::IndexChanged;
    }
    let dt = cur.t_ms - prev.t_ms;
    if dt <= 0 {
        return Rate::InvalidInterval;
    }
    if cur.uptime_cs < prev.uptime_cs {
        return Rate::Reset;
    }
    let delta = if cur.value >= prev.value {
        cur.value - prev.value
    } else if cur.bits == 32 && prev.value <= u64::from(u32::MAX) {
        // Single 32-bit wrap: plausible only if the implied rate is sane.
        (u64::from(u32::MAX) - prev.value) + cur.value + 1
    } else {
        return Rate::Reset;
    };
    let per_s = delta as f64 * 1000.0 / dt as f64;
    // A 64-bit "wrap" or absurd jump (> 400 Gbit/s) is treated as a reset, not traffic.
    if per_s > 50e9 {
        return Rate::Reset;
    }
    Rate::PerSecond(per_s)
}

// ------------------------------------------------------------------ BER / v2c

fn enc_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    enc_len(body.len(), &mut v);
    v.extend_from_slice(body);
    v
}

fn enc_int(i: i64) -> Vec<u8> {
    let b = i.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (cur, next) = (b[start], b[start + 1]);
        if (cur == 0 && next & 0x80 == 0) || (cur == 0xFF && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(0x02, &b[start..])
}

fn enc_oid(oid: &[u32]) -> Option<Vec<u8>> {
    if oid.len() < 2 {
        return None;
    }
    let mut body = vec![u8::try_from(oid[0] * 40 + oid[1]).ok()?];
    for &x in &oid[2..] {
        let mut stack = vec![(x & 0x7F) as u8];
        let mut v = x >> 7;
        while v > 0 {
            stack.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        stack.reverse();
        body.extend_from_slice(&stack);
    }
    Some(tlv(0x06, &body))
}

/// Encode a v2c GetRequest for the given OIDs.
pub fn get_request(community: &str, request_id: i32, oids: &[Vec<u32>]) -> Option<Vec<u8>> {
    let mut vbs = Vec::new();
    for o in oids {
        let mut vb = enc_oid(o)?;
        vb.extend_from_slice(&[0x05, 0x00]);
        vbs.extend_from_slice(&tlv(0x30, &vb));
    }
    let mut pdu = enc_int(i64::from(request_id));
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&tlv(0x30, &vbs));
    let mut msg = enc_int(1); // version: v2c
    msg.extend_from_slice(&tlv(0x04, community.as_bytes()));
    msg.extend_from_slice(&tlv(0xA0, &pdu));
    Some(tlv(0x30, &msg))
}

/// Decoded SNMP value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Counter32(u64),
    Gauge32(u64),
    TimeTicks(u64),
    Counter64(u64),
    Octets(Vec<u8>),
    NoSuch,
    Other(u8),
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.b.get(self.p)?;
        let l0 = *self.b.get(self.p + 1)?;
        let (len, hdr) = if l0 & 0x80 == 0 {
            (usize::from(l0), 2)
        } else {
            let n = usize::from(l0 & 0x7F);
            if n == 0 || n > 3 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | usize::from(*self.b.get(self.p + 2 + i)?);
            }
            (len, 2 + n)
        };
        let start = self.p + hdr;
        let body = self.b.get(start..start.checked_add(len)?)?;
        self.p = start + len;
        Some((tag, body))
    }
}

fn dec_uint(b: &[u8]) -> Option<u64> {
    if b.len() > 9 {
        return None;
    }
    Some(b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

fn dec_oid(b: &[u8]) -> Option<Vec<u32>> {
    let first = *b.first()?;
    let mut out = vec![u32::from(first / 40), u32::from(first % 40)];
    let mut cur: u32 = 0;
    for &x in b.get(1..)? {
        cur = cur.checked_mul(128)? | u32::from(x & 0x7F);
        if x & 0x80 == 0 {
            out.push(cur);
            cur = 0;
        }
    }
    Some(out)
}

/// Decode a GetResponse into (oid, value) pairs. Total over arbitrary input.
pub fn parse_response(msg: &[u8], expect_id: i32) -> Option<Vec<(Vec<u32>, Value)>> {
    let mut r = Rd { b: msg, p: 0 };
    let (t, seq) = r.tlv()?;
    if t != 0x30 {
        return None;
    }
    let mut s = Rd { b: seq, p: 0 };
    let _version = s.tlv()?;
    let _community = s.tlv()?;
    let (pt, pdu) = s.tlv()?;
    if pt != 0xA2 {
        return None;
    }
    let mut p = Rd { b: pdu, p: 0 };
    let (_, id) = p.tlv()?;
    if i64::try_from(dec_uint(id)?).ok()? != i64::from(expect_id) {
        return None;
    }
    let (_, err) = p.tlv()?;
    if dec_uint(err)? != 0 {
        return None;
    }
    let _idx = p.tlv()?;
    let (_, vbl) = p.tlv()?;
    let mut v = Rd { b: vbl, p: 0 };
    let mut out = Vec::new();
    while v.p < vbl.len() && out.len() < 64 {
        let (_, vb) = v.tlv()?;
        let mut x = Rd { b: vb, p: 0 };
        let (_, oid) = x.tlv()?;
        let (tag, val) = x.tlv()?;
        let value = match tag {
            0x02 => Value::Int(i64::try_from(dec_uint(val)?).unwrap_or(i64::MAX)),
            0x04 => Value::Octets(val.iter().take(256).copied().collect()),
            0x41 => Value::Counter32(dec_uint(val)?),
            0x42 => Value::Gauge32(dec_uint(val)?),
            0x43 => Value::TimeTicks(dec_uint(val)?),
            0x46 => Value::Counter64(dec_uint(val)?),
            0x80..=0x82 => Value::NoSuch,
            t => Value::Other(t),
        };
        out.push((dec_oid(oid)?, value));
    }
    Some(out)
}

/// One v2c GET over UDP with a timeout (no retries).
pub async fn get(addr: SocketAddr, community: &str, oids: &[Vec<u32>], timeout: Duration) -> Result<Vec<(Vec<u32>, Value)>, String> {
    let id: i32 = rand::random::<i32>() & 0x7FFF_FFFF;
    let req = get_request(community, id, oids).ok_or("bad oid")?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    sock.connect(addr).await.map_err(|e| e.to_string())?;
    sock.send(&req).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf)).await.map_err(|_| "timeout".to_string())?.map_err(|e| e.to_string())?;
    parse_response(buf.get(..n).unwrap_or(&[]), id).ok_or_else(|| "malformed response".into())
}

/// Common OIDs.
pub mod oid {
    pub fn sys_uptime() -> Vec<u32> {
        vec![1, 3, 6, 1, 2, 1, 1, 3, 0]
    }
    pub fn if_hc_in_octets(i: u32) -> Vec<u32> {
        vec![1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, i]
    }
    pub fn if_hc_out_octets(i: u32) -> Vec<u32> {
        vec![1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10, i]
    }
    pub fn if_oper_status(i: u32) -> Vec<u32> {
        vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 8, i]
    }
    pub fn if_in_errors(i: u32) -> Vec<u32> {
        vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 14, i]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn s(t: i64, v: u64, bits: u8, up: u64) -> CounterSample {
        CounterSample { t_ms: t, value: v, bits, uptime_cs: up, if_index: 1 }
    }

    #[test]
    fn rates_wraps_and_resets() {
        assert_eq!(rate(&s(0, 1000, 64, 10), &s(1000, 3000, 64, 110)), Rate::PerSecond(2000.0));
        // 32-bit wrap
        let r = rate(&s(0, u64::from(u32::MAX) - 99, 32, 10), &s(1000, 100, 32, 110));
        assert_eq!(r, Rate::PerSecond(200.0));
        // reboot: uptime went backwards -> reset, never a spike
        assert_eq!(rate(&s(0, 5_000_000, 64, 1000), &s(1000, 10, 64, 5)), Rate::Reset);
        // 64-bit counter going backwards without reboot -> reset
        assert_eq!(rate(&s(0, 5000, 64, 10), &s(1000, 10, 64, 110)), Rate::Reset);
        assert_eq!(rate(&s(1000, 0, 64, 1), &s(1000, 1, 64, 2)), Rate::InvalidInterval);
        let mut other = s(1000, 10, 64, 2);
        other.if_index = 2;
        assert_eq!(rate(&s(0, 0, 64, 1), &other), Rate::IndexChanged);
    }

    #[test]
    fn ber_roundtrip_via_crafted_response() {
        let oids = vec![oid::sys_uptime(), oid::if_hc_in_octets(3)];
        let req = get_request("public", 1234, &oids).unwrap();
        assert_eq!(req[0], 0x30);
        // Craft a response: same structure, PDU tag A2, values TimeTicks + Counter64.
        let mut vbs = Vec::new();
        let mut a = enc_oid(&oids[0]).unwrap();
        a.extend_from_slice(&tlv(0x43, &[0x01, 0x00]));
        vbs.extend_from_slice(&tlv(0x30, &a));
        let mut b = enc_oid(&oids[1]).unwrap();
        b.extend_from_slice(&tlv(0x46, &[0x01, 0x00, 0x00, 0x00, 0x00]));
        vbs.extend_from_slice(&tlv(0x30, &b));
        let mut pdu = enc_int(1234);
        pdu.extend_from_slice(&enc_int(0));
        pdu.extend_from_slice(&enc_int(0));
        pdu.extend_from_slice(&tlv(0x30, &vbs));
        let mut msg = enc_int(1);
        msg.extend_from_slice(&tlv(0x04, b"public"));
        msg.extend_from_slice(&tlv(0xA2, &pdu));
        let resp = tlv(0x30, &msg);
        let out = parse_response(&resp, 1234).unwrap();
        assert_eq!(out[0], (oids[0].clone(), Value::TimeTicks(256)));
        assert_eq!(out[1], (oids[1].clone(), Value::Counter64(1 << 32)));
        assert!(parse_response(&resp, 999).is_none(), "request id mismatch");
        for n in 0..resp.len() {
            let _ = parse_response(&resp[..n], 1234);
        }
    }
}
