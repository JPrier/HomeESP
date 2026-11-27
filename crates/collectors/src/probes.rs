//! Central probe execution for configured checks (TCP connect, bounded HTTP, DNS,
//! unprivileged ICMP). One function per protocol; all bounded by timeouts.

use crate::dns::{self, DnsOutcome, Expect};
use ho_domain::{CentralCheck, DnsExpectConf, DnsInfo, Outcome, ProbeKindConf, ProbeObs};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Result of one central check: the normalized probe observation.
pub type CheckResult = ProbeObs;

fn obs(
    c: &CentralCheck,
    outcome: Outcome,
    rtt: Option<Duration>,
    err: i16,
    dns: Option<DnsInfo>,
) -> ProbeObs {
    ProbeObs {
        target_id: c.id.to_string(),
        kind: kind_str(c.kind).into(),
        outcome,
        rtt_us: if outcome == Outcome::Success {
            rtt.map(|d| u32::try_from(d.as_micros()).unwrap_or(u32::MAX))
        } else {
            None
        },
        scan_overlap: false,
        dscp: 0,
        sched_late_ms: 0,
        error_code: err,
        dns,
        via_bssid: None,
    }
}

pub fn kind_str(k: ProbeKindConf) -> &'static str {
    match k {
        ProbeKindConf::Icmp => "icmp",
        ProbeKindConf::UdpEcho => "udp_echo",
        ProbeKindConf::Dns => "dns",
        ProbeKindConf::Tcp => "tcp",
        ProbeKindConf::Http => "http",
    }
}

async fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port)).await.ok()?.next()
}

/// Run one configured check. Never panics; failures become explicit outcomes.
pub async fn run_check(c: &CentralCheck) -> CheckResult {
    let timeout = Duration::from_millis(u64::from(c.timeout_ms));
    match c.kind {
        ProbeKindConf::Tcp => tcp(c, timeout).await,
        ProbeKindConf::Http => http(c, timeout).await,
        ProbeKindConf::Dns => dns_check(c, timeout).await,
        ProbeKindConf::Icmp => icmp(c, timeout).await,
        ProbeKindConf::UdpEcho => obs(c, Outcome::Unsupported, None, 0, None),
    }
}

async fn tcp(c: &CentralCheck, timeout: Duration) -> CheckResult {
    let Some(addr) = resolve(&c.host, c.port.unwrap_or(0)).await else {
        return obs(c, Outcome::ConfigError, None, 1, None);
    };
    let start = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Err(_) => obs(c, Outcome::Timeout, None, -1, None),
        Ok(Ok(_)) => obs(c, Outcome::Success, Some(start.elapsed()), 0, None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            obs(c, Outcome::RefusedUnreachable, None, 2, None)
        }
        Ok(Err(_)) => obs(c, Outcome::RefusedUnreachable, None, 3, None),
    }
}

async fn http(c: &CentralCheck, timeout: Duration) -> CheckResult {
    // Only the configured host/path; no redirects (SSRF guard), capped body.
    let scheme = if c.https { "https" } else { "http" };
    let port = c.port.map(|p| format!(":{p}")).unwrap_or_default();
    let url = format!(
        "{scheme}://{}{port}{}",
        c.host,
        c.path.as_deref().unwrap_or("/")
    );
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
    {
        Ok(cl) => cl,
        Err(_) => return obs(c, Outcome::ConfigError, None, 1, None),
    };
    let start = Instant::now();
    match client.get(&url).send().await {
        Err(e) if e.is_timeout() => obs(c, Outcome::Timeout, None, -1, None),
        Err(e) if e.is_connect() => obs(c, Outcome::RefusedUnreachable, None, 2, None),
        Err(_) => obs(c, Outcome::InvalidResponse, None, 3, None),
        Ok(mut resp) => {
            let ttfb = start.elapsed();
            let status = resp.status().as_u16();
            // Drain at most 64 KiB; the body is never stored.
            let mut read = 0usize;
            while let Ok(Some(chunk)) = resp.chunk().await {
                read += chunk.len();
                if read > 65_536 {
                    break;
                }
            }
            let ok = match c.expect_status {
                Some(s) => s == status,
                None => (200..400).contains(&status),
            };
            if ok {
                obs(c, Outcome::Success, Some(ttfb), 0, None)
            } else {
                obs(
                    c,
                    Outcome::InvalidResponse,
                    None,
                    i16::try_from(status).unwrap_or(i16::MAX),
                    None,
                )
            }
        }
    }
}

fn expect_of(c: &CentralCheck) -> Expect {
    match &c.expect {
        Some(DnsExpectConf::Nxdomain) => Expect::Nxdomain,
        Some(DnsExpectConf::Ipv4 { address }) => match address.parse::<std::net::Ipv4Addr>() {
            Ok(a) => Expect::Ipv4(a.octets()),
            Err(_) => Expect::AnyAnswer,
        },
        _ => Expect::AnyAnswer,
    }
}

async fn dns_check(c: &CentralCheck, timeout: Duration) -> CheckResult {
    let Some(server) = resolve(&c.host, c.port.unwrap_or(53)).await else {
        return obs(c, Outcome::ConfigError, None, 1, None);
    };
    let qname = c.qname.clone().unwrap_or_default();
    let qtype = c.qtype.unwrap_or(1);
    let res = dns::query_udp(server, &qname, qtype, expect_of(c), timeout).await;
    match res {
        DnsOutcome::Timeout => obs(
            c,
            Outcome::Timeout,
            None,
            -1,
            Some(DnsInfo {
                rcode: 0,
                answer: "no_answer".into(),
                transport: "udp".into(),
                qtype,
            }),
        ),
        DnsOutcome::Error(_) => obs(c, Outcome::RefusedUnreachable, None, 2, None),
        DnsOutcome::Answered { rtt, result } => {
            let info = DnsInfo {
                rcode: result.rcode,
                answer: result.answer.into(),
                transport: "udp".into(),
                qtype,
            };
            if result.answer == "malformed" {
                obs(c, Outcome::InvalidResponse, None, 3, Some(info))
            } else {
                obs(c, Outcome::Success, Some(rtt), 0, Some(info))
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn icmp(c: &CentralCheck, timeout: Duration) -> CheckResult {
    // Unprivileged ICMP "ping socket" (requires net.ipv4.ping_group_range to include
    // the service's group; no CAP_NET_RAW needed).
    use socket2::{Domain, Protocol, Socket, Type};
    let Some(addr) = resolve(&c.host, 0).await else {
        return obs(c, Outcome::ConfigError, None, 1, None);
    };
    let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return obs(c, Outcome::Unsupported, None, 4, None),
    };
    if sock.set_nonblocking(true).is_err() {
        return obs(c, Outcome::Unsupported, None, 4, None);
    }
    let std_sock: std::net::UdpSocket = sock.into();
    let Ok(s) = tokio::net::UdpSocket::from_std(std_sock) else {
        return obs(c, Outcome::Unsupported, None, 4, None);
    };
    let seq: u16 = rand::random();
    let mut pkt = vec![8u8, 0, 0, 0, 0, 0];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&[0x48; 24]);
    let start = Instant::now();
    if s.send_to(&pkt, addr).await.is_err() {
        return obs(c, Outcome::RefusedUnreachable, None, 5, None);
    }
    let mut buf = [0u8; 256];
    let deadline = start + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, s.recv_from(&mut buf)).await {
            Err(_) => return obs(c, Outcome::Timeout, None, -1, None),
            Ok(Err(_)) => return obs(c, Outcome::RefusedUnreachable, None, 6, None),
            Ok(Ok((n, _))) => {
                if n >= 8
                    && buf.first() == Some(&0)
                    && buf.get(6..8) == Some(&seq.to_be_bytes()[..])
                {
                    return obs(c, Outcome::Success, Some(start.elapsed()), 0, None);
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn icmp(c: &CentralCheck, _timeout: Duration) -> CheckResult {
    // Raw ICMP would need elevated privileges here; report it honestly.
    obs(c, Outcome::Unsupported, None, 4, None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use ho_domain::TargetId;

    fn check(kind: ProbeKindConf, host: &str, port: Option<u16>) -> CentralCheck {
        CentralCheck {
            id: TargetId::new("t1").unwrap(),
            kind,
            host: host.into(),
            port,
            qname: None,
            qtype: None,
            expect: None,
            path: None,
            https: false,
            expect_status: None,
            interval_ms: 5000,
            timeout_ms: 300,
            asset: None,
            critical: false,
            compare_with: None,
        }
    }

    #[tokio::test]
    async fn tcp_success_refused_and_no_rtt_on_failure() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let ok = run_check(&check(ProbeKindConf::Tcp, "127.0.0.1", Some(port))).await;
        assert_eq!(ok.outcome, Outcome::Success);
        assert!(ok.rtt_us.is_some());
        drop(l);
        let refused = run_check(&check(ProbeKindConf::Tcp, "127.0.0.1", Some(port))).await;
        assert_ne!(refused.outcome, Outcome::Success);
        assert_eq!(refused.rtt_us, None, "a failed probe never carries an RTT");
    }

    #[tokio::test]
    async fn http_status_expectation_and_no_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = l.accept().await.unwrap();
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                s.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            }
        });
        let mut c = check(ProbeKindConf::Http, "127.0.0.1", Some(port));
        c.path = Some("/health".into());
        let r = run_check(&c).await;
        assert_eq!(
            r.outcome,
            Outcome::Success,
            "3xx counts as up by default, but is not followed"
        );
        c.expect_status = Some(200);
        let r = run_check(&c).await;
        assert_eq!(r.outcome, Outcome::InvalidResponse);
        assert_eq!(r.error_code, 302);
    }

    #[tokio::test]
    async fn udp_echo_is_not_a_central_check() {
        let r = run_check(&check(ProbeKindConf::UdpEcho, "127.0.0.1", Some(1))).await;
        assert_eq!(r.outcome, Outcome::Unsupported);
    }
}
