//! Build per-node desired configuration frames and ACK frames.

use ho_domain::{parse_mac, AddrConf, DnsExpectConf, NodeConf, ProbeKindConf, SiteConfig};
use ho_protocol as p;

fn kind(k: ProbeKindConf) -> p::ProbeKind {
    match k {
        ProbeKindConf::Icmp => p::ProbeKind::Icmp,
        ProbeKindConf::UdpEcho => p::ProbeKind::UdpEcho,
        ProbeKindConf::Dns => p::ProbeKind::Dns,
        ProbeKindConf::Tcp => p::ProbeKind::Tcp,
        ProbeKindConf::Http => p::ProbeKind::Http,
    }
}

/// Owned probe target (borrowed into the wire record at encode time).
struct Target {
    id: String,
    kind: p::ProbeKind,
    src: p::AddrSource,
    ip: [u8; 4],
    port: u16,
    interval_ms: u32,
    timeout_ms: u16,
    expect: p::DnsExpect,
    expect_ip: [u8; 4],
    qtype: u16,
    qname: String,
}

fn targets_for(cfg: &SiteConfig, node: &NodeConf) -> Vec<Target> {
    let prof = cfg.profile_for(node);
    let mut out: Vec<Target> = Vec::new();
    for t in cfg.probe_targets.iter().filter(|t| t.nodes.is_empty() || t.nodes.contains(&node.id)) {
        if t.kind == ProbeKindConf::Http {
            continue; // nodes do not run HTTP probes
        }
        let (src, ip) = match &t.addr {
            AddrConf::Gateway => (p::AddrSource::Gateway, [0; 4]),
            AddrConf::AssignedResolver => (p::AddrSource::AssignedResolver, [0; 4]),
            AddrConf::Server => (p::AddrSource::Server, [0; 4]),
            AddrConf::Ipv4(a) => match a.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => (p::AddrSource::Literal, ip.octets()),
                Err(_) => continue,
            },
        };
        let default_interval = match t.kind {
            ProbeKindConf::Dns => prof.dns_probe_ms,
            ProbeKindConf::UdpEcho => prof.udp_probe_ms,
            _ => prof.gateway_probe_ms,
        };
        let (expect, expect_ip) = match &t.expect {
            Some(DnsExpectConf::Nxdomain) => (p::DnsExpect::Nxdomain, [0; 4]),
            Some(DnsExpectConf::Ipv4 { address }) => {
                (p::DnsExpect::Ipv4, address.parse::<std::net::Ipv4Addr>().map(|a| a.octets()).unwrap_or([0; 4]))
            }
            _ => (p::DnsExpect::AnyAnswer, [0; 4]),
        };
        out.push(Target {
            id: t.id.to_string(),
            kind: kind(t.kind),
            src,
            ip,
            port: t.port.unwrap_or(0),
            interval_ms: t.interval_ms.unwrap_or(default_interval),
            timeout_ms: t.timeout_ms.unwrap_or(prof.probe_timeout_ms),
            expect,
            expect_ip,
            qtype: t.qtype.unwrap_or(if t.kind == ProbeKindConf::Dns { 1 } else { 0 }),
            qname: t.qname.clone().unwrap_or_default(),
        });
    }
    // Baseline probes always present unless the operator configured the same ids.
    let builtin = [
        ("gw-icmp", p::ProbeKind::Icmp, p::AddrSource::Gateway, prof.gateway_probe_ms),
        ("server-icmp", p::ProbeKind::Icmp, p::AddrSource::Server, prof.server_probe_ms),
        ("server-udp", p::ProbeKind::UdpEcho, p::AddrSource::Server, prof.udp_probe_ms),
    ];
    for (id, k, src, interval) in builtin {
        if interval == 0 || out.iter().any(|t| t.id == id) || out.len() >= 8 {
            continue;
        }
        out.insert(
            0,
            Target {
                id: id.into(),
                kind: k,
                src,
                ip: [0; 4],
                port: 0,
                interval_ms: interval,
                timeout_ms: prof.probe_timeout_ms,
                expect: p::DnsExpect::AnyAnswer,
                expect_ip: [0; 4],
                qtype: 0,
                qname: String::new(),
            },
        );
    }
    out.truncate(8);
    out
}

/// Encode the desired-config frame for `node` at `revision`.
pub fn desired_frame(cfg: &SiteConfig, node: &NodeConf, revision: u64, seq: u64) -> Result<Vec<u8>, String> {
    let prof = cfg.profile_for(node);
    let mut flags = 0u16;
    if prof.passive_scan_enabled {
        flags |= p::cfgflag::PASSIVE_SCAN;
    }
    if prof.ble_enabled {
        flags |= p::cfgflag::BLE_SCAN;
    }
    if prof.csi_enabled && cfg.experimental.csi {
        flags |= p::cfgflag::CSI;
    }
    let params = p::ConfigParams {
        revision,
        report_ms: prof.report_ms,
        wifi_link_ms: prof.wifi_link_ms,
        ap_scan_ms: if prof.passive_scan_enabled { prof.neighbor_scan_ms } else { 0 },
        heartbeat_ms: prof.heartbeat_ms,
        health_ms: prof.health_ms,
        egress_bytes_per_sec: prof.egress_bytes_per_sec,
        egress_burst_bytes: prof.egress_burst_bytes,
        max_payload: prof.max_publish_payload_bytes,
        offline_buffer_bytes: prof.max_offline_buffer_bytes,
        flags,
        max_probe_inflight: prof.max_probe_inflight,
        scan_max_dwell_ms: prof.scan_max_dwell_ms,
    };
    let targets = targets_for(cfg, node);
    let bssids: Vec<[u8; 6]> = cfg.radios.iter().filter_map(|r| parse_mac(&r.bssid)).take(16).collect();
    let header = p::Header {
        kind: p::MsgKind::ConfigDesired,
        flags: 0,
        node_id: node.id.as_str(),
        boot_id: [0; 16],
        sequence: seq,
        sent_mono_ms: 0,
        config_revision: revision,
    };
    let mut buf = [0u8; p::MAX_FRAME_BYTES];
    let mut w = p::FrameWriter::new(&mut buf, &header, p::MAX_FRAME_BYTES).map_err(|e| format!("{e:?}"))?;
    w.push(&p::Record::ConfigParams(params)).map_err(|e| format!("{e:?}"))?;
    for t in &targets {
        w.push(&p::Record::ProbeTarget(p::ProbeTarget {
            id: &t.id,
            kind: t.kind,
            addr_source: t.src,
            ipv4: t.ip,
            port: t.port,
            interval_ms: t.interval_ms,
            timeout_ms: t.timeout_ms,
            dscp: 0,
            expect: t.expect,
            expect_ipv4: t.expect_ip,
            qtype: t.qtype,
            qname: &t.qname,
        }))
        .map_err(|e| format!("target {}: {e:?}", t.id))?;
    }
    for b in &bssids {
        w.push(&p::Record::TrackedBssid(*b)).map_err(|e| format!("{e:?}"))?;
    }
    let n = w.finish();
    Ok(buf.get(..n).unwrap_or(&[]).to_vec())
}

/// Encode a durable-ACK frame for an events batch.
pub fn ack_frame(node: &str, boot: [u8; 16], seq: u64, server_seq: u64) -> Result<Vec<u8>, String> {
    let header = p::Header {
        kind: p::MsgKind::Ack,
        flags: 0,
        node_id: node,
        boot_id: [0; 16],
        sequence: server_seq,
        sent_mono_ms: 0,
        config_revision: 0,
    };
    let mut buf = [0u8; 128];
    let mut w = p::FrameWriter::new(&mut buf, &header, 128).map_err(|e| format!("{e:?}"))?;
    w.push(&p::Record::Ack(p::Ack { boot_id: boot, sequence: seq })).map_err(|e| format!("{e:?}"))?;
    let n = w.finish();
    Ok(buf.get(..n).unwrap_or(&[]).to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn desired_frame_roundtrips_and_includes_baseline_probes() {
        let cfg = SiteConfig::from_yaml_str(
            r#"
schema_version: 1
site_id: home
nodes: [{id: node-01}]
assets: [{id: gw, kind: router}, {id: ap, kind: access_point}]
radios: [{bssid: "02:00:00:00:00:01", ap: ap, band: "2.4"}]
probe_targets:
  - {id: dns-local, kind: dns, addr: assigned_resolver, qname: router.home.arpa, expect: {type: ipv4, address: 192.0.2.1}}
"#,
        )
        .unwrap();
        let f = desired_frame(&cfg, &cfg.nodes[0], 7, 1).unwrap();
        let d = p::decode_frame(&f).unwrap();
        assert_eq!(d.header.kind, p::MsgKind::ConfigDesired);
        assert_eq!(d.header.node_id, "node-01");
        let recs: Vec<_> = d.records().collect();
        let ids: Vec<&str> = recs
            .iter()
            .filter_map(|r| if let p::Record::ProbeTarget(t) = r { Some(t.id) } else { None })
            .collect();
        assert_eq!(ids, vec!["server-udp", "server-icmp", "gw-icmp", "dns-local"]);
        assert!(recs.iter().any(|r| matches!(r, p::Record::TrackedBssid(_))));
        match recs[0] {
            p::Record::ConfigParams(c) => {
                assert_eq!(c.revision, 7);
                assert_eq!(c.flags & p::cfgflag::BLE_SCAN, 0, "BLE off by default");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ack_frame_decodes() {
        let f = ack_frame("node-01", [3; 16], 42, 1).unwrap();
        let d = p::decode_frame(&f).unwrap();
        assert!(matches!(d.records().next(), Some(p::Record::Ack(a)) if a.sequence == 42 && a.boot_id == [3; 16]));
    }
}
