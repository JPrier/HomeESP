//! Transparent network quality score and evidence-based advisory recommendations
//! (spec §12.4, §12.5). Advisory only: nothing here changes any device.

use crate::engine::{EngineSnapshot, TargetSummary};
use ho_domain::{Health, NodeLiveness};
use serde::Serialize;

/// Score version; bump when weights/semantics change.
pub const SCORE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Score {
    pub version: u32,
    /// `None` when coverage is insufficient (we do not invent a number).
    pub value: Option<f64>,
    pub coverage: f64,
    pub components: Vec<(String, Option<f64>)>,
    pub worst_vantage: Option<String>,
}

fn component(ts: &[&TargetSummary], f: impl Fn(&TargetSummary) -> Option<f64>) -> Option<f64> {
    let vals: Vec<f64> = ts.iter().filter_map(|t| f(t)).collect();
    if vals.is_empty() {
        None
    } else {
        Some(vals.iter().sum::<f64>() / vals.len() as f64)
    }
}

/// Score in [0, 100] from loss, p95 latency and DNS availability. Each component
/// must have >= `min_samples`; missing components lower coverage instead of the score.
pub fn score(s: &EngineSnapshot, min_samples: u32) -> Score {
    let usable: Vec<&TargetSummary> = s
        .targets
        .iter()
        .filter(|t| t.stats.eligible >= min_samples)
        .collect();
    let ip: Vec<&TargetSummary> = usable
        .iter()
        .copied()
        .filter(|t| t.kind == "icmp" || t.kind == "udp_echo")
        .collect();
    let dns: Vec<&TargetSummary> = usable.iter().copied().filter(|t| t.kind == "dns").collect();
    let loss = component(&ip, |t| {
        t.stats
            .loss_pct
            .map(|l| (100.0 - l * 10.0).clamp(0.0, 100.0))
    });
    let lat = component(&ip, |t| {
        t.stats
            .p95_ms
            .map(|p| (100.0 - (p - 10.0).max(0.0)).clamp(0.0, 100.0))
    });
    let dns_av = component(&dns, |t| {
        (t.stats.eligible > 0).then(|| {
            100.0 * f64::from(t.stats.successes.saturating_sub(t.stats.dns_bad))
                / f64::from(t.stats.eligible)
        })
    });
    let comps = vec![
        ("loss".to_string(), loss),
        ("latency_p95".to_string(), lat),
        ("dns".to_string(), dns_av),
    ];
    let present: Vec<f64> = comps.iter().filter_map(|c| c.1).collect();
    let coverage = present.len() as f64 / comps.len() as f64;
    let value = (coverage >= 2.0 / 3.0).then(|| present.iter().sum::<f64>() / present.len() as f64);
    let worst_vantage = usable
        .iter()
        .filter(|t| t.stats.p95_ms.is_some())
        .max_by(|a, b| {
            a.stats
                .p95_ms
                .unwrap_or(0.0)
                .total_cmp(&b.stats.p95_ms.unwrap_or(0.0))
        })
        .map(|t| t.vantage.clone());
    Score {
        version: SCORE_VERSION,
        value,
        coverage,
        components: comps,
        worst_vantage,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub confidence: String,
    pub evidence: Vec<String>,
    pub expected_effect: String,
    pub alternatives: Vec<String>,
    pub verification: String,
}

/// Rule-based advisory findings from the current snapshot.
pub fn recommendations(s: &EngineSnapshot) -> Vec<Recommendation> {
    let mut out = Vec::new();
    for n in &s.nodes {
        if let Some(r) = n.state.rssi_dbm {
            if r <= -75 && n.liveness == NodeLiveness::Online {
                out.push(Recommendation {
                    id: format!("weak-signal:{}", n.id),
                    title: format!("Weak Wi-Fi signal at node {}", n.id),
                    confidence: "medium".into(),
                    evidence: vec![format!("current RSSI {r} dBm (2.4 GHz)")],
                    expected_effect: "fewer retries and lower tail latency for clients in this area".into(),
                    alternatives: vec!["reposition the node".into(), "add/move an AP".into(), "wired backhaul".into()],
                    verification: "compare p95 RTT and RSSI for this vantage over matched before/after windows".into(),
                });
            }
        }
        if let Some(sys) = &n.state.last_system {
            if u32::from(sys.drops_overflow)
                + u32::from(sys.drops_budget)
                + u32::from(sys.drops_expired)
                > 0
            {
                out.push(Recommendation {
                    id: format!("node-drops:{}", n.id),
                    title: format!("Node {} dropped telemetry", n.id),
                    confidence: "high".into(),
                    evidence: vec![format!(
                        "drops overflow={} budget={} expired={}",
                        sys.drops_overflow, sys.drops_budget, sys.drops_expired
                    )],
                    expected_effect: "no silent gaps in history".into(),
                    alternatives: vec![
                        "raise egress budget slightly".into(),
                        "lengthen report interval".into(),
                    ],
                    verification: "drop counters stay flat for 24 h".into(),
                });
            }
        }
    }
    let channels: Vec<u8> = s.nodes.iter().filter_map(|n| n.state.channel).collect();
    if channels.len() >= 2 && channels.iter().all(|c| *c == channels[0]) {
        out.push(Recommendation {
            id: "channel-overlap".into(),
            title: "All nodes see their AP on the same 2.4 GHz channel".into(),
            confidence: "low".into(),
            evidence: vec![format!(
                "channel {} for {} nodes",
                channels[0],
                channels.len()
            )],
            expected_effect: "less co-channel contention if multiple APs share it".into(),
            alternatives: vec!["this is expected with a single AP".into()],
            verification: "review AP channel plan and neighbor channel counts in scans".into(),
        });
    }
    for t in &s.targets {
        if t.kind == "dns" && t.health == Health::Degraded {
            out.push(Recommendation {
                id: format!("dns:{}:{}", t.vantage, t.target),
                title: format!("Investigate resolver failures seen from {}", t.vantage),
                confidence: "medium".into(),
                evidence: vec![t.reason.clone()],
                expected_effect: "fewer client DNS stalls".into(),
                alternatives: vec!["UDP loss on the path".into(), "resolver overload".into()],
                verification: "DNS matrix: compare wired vs wireless and UDP vs TCP".into(),
            });
        }
    }
    out
}
