//! DNS query builder/classifier (same semantics as the firmware's `ho_dns`), plus
//! explicit UDP and TCP transactions against a configured resolver.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    AnyAnswer,
    Nxdomain,
    Ipv4([u8; 4]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub rcode: u8,
    /// Same vocabulary as the wire protocol's DnsAnswer.
    pub answer: &'static str,
    pub error: Option<&'static str>,
}

/// Build a recursive query. `None` if the name is invalid.
pub fn build_query(id: u16, qname: &str, qtype: u16) -> Option<Vec<u8>> {
    if !ho_domain::valid_qname(qname) {
        return None;
    }
    let mut q = Vec::with_capacity(12 + qname.len() + 6);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in qname.split('.') {
        q.push(u8::try_from(label.len()).ok()?);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    Some(q)
}

fn rd16(m: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(at)?, *m.get(at + 1)?]))
}

fn skip_name(m: &[u8], mut p: usize) -> Option<usize> {
    for _ in 0..128 {
        let l = *m.get(p)?;
        if l == 0 {
            return Some(p + 1);
        }
        if l & 0xC0 == 0xC0 {
            m.get(p + 1)?;
            return Some(p + 2);
        }
        if l & 0xC0 != 0 {
            return None;
        }
        p += 1 + usize::from(l);
    }
    None
}

/// Classify a response. Total over arbitrary input.
pub fn classify(m: &[u8], id: u16, expect: Expect) -> Classified {
    let bad = |e| Classified {
        rcode: 0,
        answer: "malformed",
        error: Some(e),
    };
    let Some(rid) = rd16(m, 0) else {
        return bad("short");
    };
    if rid != id {
        return bad("id_mismatch");
    }
    let (Some(f1), Some(f2)) = (m.get(2), m.get(3)) else {
        return bad("short");
    };
    if f1 & 0x80 == 0 {
        return bad("not_response");
    }
    let rcode = f2 & 0x0F;
    let tc = f1 & 0x02 != 0;
    let (Some(qd), Some(an)) = (rd16(m, 4), rd16(m, 6)) else {
        return bad("short");
    };
    let mut pos = 12usize;
    for _ in 0..qd {
        match skip_name(m, pos) {
            Some(p) if p + 4 <= m.len() => pos = p + 4,
            _ => return bad("question"),
        }
    }
    let mk = |answer| Classified {
        rcode,
        answer,
        error: None,
    };
    match rcode {
        0 => {}
        2 => return mk("servfail"),
        3 => {
            return mk(if expect == Expect::Nxdomain {
                "expected_nxdomain"
            } else {
                "unexpected_nxdomain"
            })
        }
        5 => return mk("refused"),
        _ => return mk("malformed"),
    }
    if tc {
        return Classified {
            rcode,
            answer: "no_answer",
            error: Some("truncated"),
        };
    }
    if an == 0 {
        return mk(if expect == Expect::Nxdomain {
            "mismatch"
        } else {
            "no_answer"
        });
    }
    if expect == Expect::Nxdomain {
        return mk("mismatch");
    }
    let mut matched = false;
    for _ in 0..an.min(32) {
        let Some(p) = skip_name(m, pos) else {
            return bad("answer");
        };
        let (Some(ty), Some(rdlen)) = (rd16(m, p), rd16(m, p + 8)) else {
            return bad("answer");
        };
        let start = p + 10;
        let end = start + usize::from(rdlen);
        let Some(rdata) = m.get(start..end) else {
            return bad("rdata");
        };
        if let Expect::Ipv4(ip) = expect {
            if ty == 1 && rdata == ip {
                matched = true;
            }
        }
        pos = end;
    }
    match expect {
        Expect::Ipv4(_) => mk(if matched { "match" } else { "mismatch" }),
        _ => mk("match"),
    }
}

/// Outcome of one DNS transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsOutcome {
    Answered { rtt: Duration, result: Classified },
    Timeout,
    Error(String),
}

/// One UDP DNS transaction: exactly one query, no retries (no retry storms).
pub async fn query_udp(
    server: SocketAddr,
    qname: &str,
    qtype: u16,
    expect: Expect,
    timeout: Duration,
) -> DnsOutcome {
    let id: u16 = rand::random();
    let Some(q) = build_query(id, qname, qtype) else {
        return DnsOutcome::Error("invalid qname".into());
    };
    let bind: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => return DnsOutcome::Error(e.to_string()),
    };
    if let Err(e) = sock.connect(server).await {
        return DnsOutcome::Error(e.to_string());
    }
    let start = Instant::now();
    if let Err(e) = sock.send(&q).await {
        return DnsOutcome::Error(e.to_string());
    }
    let mut buf = [0u8; 1500];
    let deadline = start + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, sock.recv(&mut buf)).await {
            Err(_) => return DnsOutcome::Timeout,
            Ok(Err(e)) => return DnsOutcome::Error(e.to_string()),
            Ok(Ok(n)) => {
                let r = classify(buf.get(..n).unwrap_or(&[]), id, expect);
                if r.error == Some("id_mismatch") {
                    continue; // stray datagram; keep waiting until the deadline
                }
                return DnsOutcome::Answered {
                    rtt: start.elapsed(),
                    result: r,
                };
            }
        }
    }
}

/// One TCP DNS transaction (RFC 7766 length-prefixed).
pub async fn query_tcp(
    server: SocketAddr,
    qname: &str,
    qtype: u16,
    expect: Expect,
    timeout: Duration,
) -> DnsOutcome {
    let id: u16 = rand::random();
    let Some(q) = build_query(id, qname, qtype) else {
        return DnsOutcome::Error("invalid qname".into());
    };
    let start = Instant::now();
    let fut = async {
        let mut s = TcpStream::connect(server).await?;
        let len = u16::try_from(q.len()).map_err(|_| std::io::Error::other("query too long"))?;
        s.write_all(&len.to_be_bytes()).await?;
        s.write_all(&q).await?;
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await?;
        let n = usize::from(u16::from_be_bytes(lb));
        let mut buf = vec![0u8; n.min(4096)];
        s.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => DnsOutcome::Timeout,
        Ok(Err(e)) => DnsOutcome::Error(e.to_string()),
        Ok(Ok(buf)) => DnsOutcome::Answered {
            rtt: start.elapsed(),
            result: classify(&buf, id, expect),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn response(q: &[u8], rcode: u8, answers: &[[u8; 4]]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] = 0x81;
        r[3] = 0x80 | rcode;
        r[7] = answers.len() as u8;
        for a in answers {
            r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            r.extend_from_slice(a);
        }
        r
    }

    #[test]
    fn classify_matrix() {
        let q = build_query(7, "router.home.arpa", 1).unwrap();
        assert_eq!(q.len(), 12 + 18 + 4);
        let ok = response(&q, 0, &[[192, 0, 2, 10]]);
        assert_eq!(
            classify(&ok, 7, Expect::Ipv4([192, 0, 2, 10])).answer,
            "match"
        );
        assert_eq!(
            classify(&ok, 7, Expect::Ipv4([192, 0, 2, 11])).answer,
            "mismatch"
        );
        assert_eq!(
            classify(&ok, 8, Expect::AnyAnswer).error,
            Some("id_mismatch")
        );
        assert_eq!(
            classify(&response(&q, 3, &[]), 7, Expect::Nxdomain).answer,
            "expected_nxdomain"
        );
        assert_eq!(
            classify(&response(&q, 3, &[]), 7, Expect::AnyAnswer).answer,
            "unexpected_nxdomain"
        );
        assert_eq!(
            classify(&response(&q, 2, &[]), 7, Expect::AnyAnswer).answer,
            "servfail"
        );
        assert_eq!(
            classify(&response(&q, 5, &[]), 7, Expect::AnyAnswer).answer,
            "refused"
        );
        assert_eq!(
            classify(&response(&q, 0, &[]), 7, Expect::AnyAnswer).answer,
            "no_answer"
        );
        assert_eq!(
            classify(&ok[..ok.len() - 2], 7, Expect::Ipv4([192, 0, 2, 10])).answer,
            "malformed"
        );
        assert!(build_query(1, "bad..name", 1).is_none());
    }

    #[test]
    fn classify_is_total() {
        let mut x: u32 = 1;
        for len in 0..200usize {
            let mut v = vec![0u8; len];
            for b in v.iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *b = x as u8;
            }
            if len >= 2 {
                v[0] = 0;
                v[1] = 9;
            }
            let _ = classify(&v, 9, Expect::AnyAnswer);
        }
    }

    #[tokio::test]
    async fn udp_transaction_against_local_fake_resolver() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = srv.recv_from(&mut buf).await.unwrap();
            let r = response(&buf[..n], 0, &[[192, 0, 2, 10]]);
            srv.send_to(&r, from).await.unwrap();
        });
        let out = query_udp(
            addr,
            "router.home.arpa",
            1,
            Expect::Ipv4([192, 0, 2, 10]),
            Duration::from_secs(1),
        )
        .await;
        match out {
            DnsOutcome::Answered { result, .. } => assert_eq!(result.answer, "match"),
            other => panic!("{other:?}"),
        }
        // Nobody answers -> timeout, not success.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let out = query_udp(
            dead.local_addr().unwrap(),
            "a.b",
            1,
            Expect::AnyAnswer,
            Duration::from_millis(100),
        )
        .await;
        assert_eq!(out, DnsOutcome::Timeout);
    }
}
