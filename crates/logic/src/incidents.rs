//! Deterministic, explainable incident correlation (spec §12.3) and lifecycle.
//!
//! `correlate` turns a snapshot of current states into root-cause *hypotheses*, each
//! with supporting and contradicting evidence, a confidence class (never a made-up
//! probability), alternatives and a next diagnostic step. Symptoms explained by a
//! broader hypothesis (e.g. nodes behind a failed AP) are grouped under it as
//! evidence instead of opening separate incidents.

use ho_domain::{AssetKind, Health, NodeLiveness, Severity, SiteConfig, Thresholds, UnixMs};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Vantage name used for the wired central server.
pub const CENTRAL: &str = "central";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypKind {
    ObservabilityOutage,
    ApUnavailable,
    ApRadioIssue,
    NodeMissing,
    DnsResolver,
    DnsClientPath,
    WanOutage,
    WirelessPathDegraded,
    SharedLanCongestion,
    AssetUnreachable,
    ServiceFailure,
    UnknownDegradation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub key: String,
    pub kind: HypKind,
    pub severity: Severity,
    pub title: String,
    pub cause: String,
    pub confidence: Confidence,
    pub scope_assets: Vec<String>,
    pub affected_nodes: Vec<String>,
    pub evidence: Vec<String>,
    pub contradicting: Vec<String>,
    pub alternatives: Vec<String>,
    pub next_check: String,
}

/// What correlation needs to know about a node.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeView {
    pub id: String,
    pub liveness: NodeLiveness,
    /// AP asset the node is (or was last) associated with.
    pub ap: Option<String>,
}

/// What correlation needs to know about one target from one vantage.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetView {
    pub vantage: String,
    pub target_id: String,
    pub kind: String,
    pub asset: Option<String>,
    pub critical: bool,
    pub health: Health,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoamView {
    pub node: String,
    pub from_ap: String,
    pub to_ap: Option<String>,
    pub at: UnixMs,
}

/// Radio visibility from completed passive scans in the correlation window.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RadioView {
    pub ap: String,
    /// Nodes whose complete scans saw this AP's BSSIDs recently.
    pub seen_by: BTreeSet<String>,
    /// Nodes that completed scans recently but did NOT see it (and saw it before).
    pub absent_for: BTreeSet<String>,
}

pub struct Snapshot<'a> {
    pub config: &'a SiteConfig,
    pub now: UnixMs,
    pub ingestion_ok: bool,
    pub nodes: &'a [NodeView],
    pub targets: &'a [TargetView],
    pub roams: &'a [RoamView],
    pub radios: &'a [RadioView],
}

fn is_wired(t: &TargetView) -> bool {
    t.vantage == CENTRAL
}

fn asset_kind(cfg: &SiteConfig, id: Option<&str>) -> Option<AssetKind> {
    id.and_then(|a| cfg.asset(a)).map(|a| a.kind)
}

fn sev_for_asset(cfg: &SiteConfig, id: &str, default: Severity) -> Severity {
    match cfg.asset(id) {
        Some(a) if a.critical => Severity::Critical,
        _ => default,
    }
}

/// Correlate current state into hypotheses. Pure and deterministic (sorted output).
pub fn correlate(s: &Snapshot<'_>) -> Vec<Hypothesis> {
    let cfg = s.config;
    let window = cfg.thresholds.correlation_window_ms;
    let mut out: Vec<Hypothesis> = Vec::new();
    let mut absorbed_nodes: BTreeSet<String> = BTreeSet::new();

    // R0: the observability pipeline itself is down: node state is unknown, so we
    // suppress node-derived claims entirely (S09).
    if !s.ingestion_ok {
        out.push(Hypothesis {
            key: "observability".into(),
            kind: HypKind::ObservabilityOutage,
            severity: Severity::Warning,
            title: "Telemetry ingestion unavailable".into(),
            cause: "MQTT broker or ingestion path is down; node states are unknown".into(),
            confidence: Confidence::High,
            scope_assets: vec![],
            affected_nodes: vec![],
            evidence: vec!["server lost its broker session / ingestion is not receiving".into()],
            contradicting: vec![],
            alternatives: vec!["broker restart in progress".into()],
            next_check: "check broker process/logs and server MQTT connection".into(),
        });
    }

    let fresh_roams: Vec<&RoamView> = s.roams.iter().filter(|r| s.now - r.at <= window * 5).collect();
    let central = |asset: &str| -> Vec<&TargetView> {
        s.targets.iter().filter(|t| is_wired(t) && t.asset.as_deref() == Some(asset)).collect()
    };

    // R1/R2: AP-level grouping.
    if s.ingestion_ok {
        let aps: Vec<&str> =
            cfg.assets.iter().filter(|a| a.kind == AssetKind::AccessPoint).map(|a| a.id.as_str()).collect();
        for ap in aps {
            let missing: Vec<&NodeView> =
                s.nodes.iter().filter(|n| n.liveness == NodeLiveness::Missing && n.ap.as_deref() == Some(ap)).collect();
            let roamed: Vec<&RoamView> = fresh_roams.iter().copied().filter(|r| r.from_ap == ap).collect();
            let affected: BTreeSet<String> =
                missing.iter().map(|n| n.id.clone()).chain(roamed.iter().map(|r| r.node.clone())).collect();
            let mgmt = central(ap);
            let mgmt_failed = mgmt.iter().any(|t| t.health == Health::Failed);
            let mgmt_healthy = !mgmt.is_empty() && mgmt.iter().all(|t| t.health == Health::Healthy);
            let radio = s.radios.iter().find(|r| r.ap == ap);
            let radio_absent = radio.is_some_and(|r| r.absent_for.len() >= 2 && r.seen_by.is_empty());
            // Roams are only supporting evidence; a hypothesis needs a *current*
            // symptom (a node still missing, failing management, or an absent radio),
            // otherwise it could never resolve while old roams remain in the window.
            let current = !missing.is_empty() || mgmt_failed || radio_absent;
            if current && (affected.len() >= 2 || (radio_absent && mgmt_healthy)) {
                let mut evidence: Vec<String> = Vec::new();
                for n in &missing {
                    evidence.push(format!("node {} missing; last associated with {ap}", n.id));
                }
                for r in &roamed {
                    evidence.push(format!(
                        "node {} roamed away from {ap}{}",
                        r.node,
                        r.to_ap.as_ref().map(|t| format!(" to {t}")).unwrap_or_default()
                    ));
                }
                if let Some(r) = radio {
                    if !r.absent_for.is_empty() {
                        evidence.push(format!(
                            "{ap} radio absent from complete scans by {}",
                            r.absent_for.iter().cloned().collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
                let mut contradicting = Vec::new();
                let (kind, cause, confidence, alts, next) = if mgmt_healthy {
                    for t in &mgmt {
                        contradicting.push(format!("management check {} healthy", t.target_id));
                    }
                    (
                        HypKind::ApRadioIssue,
                        format!("{ap} management reachable but its radio is unavailable or misconfigured"),
                        if radio_absent { Confidence::High } else { Confidence::Medium },
                        vec!["radio disabled by controller".into(), "channel/power change".into()],
                        "inspect the AP radio state/channel in its controller".into(),
                    )
                } else {
                    for t in &mgmt {
                        evidence.push(format!("management check {} {}: {}", t.target_id, t.health.as_str(), t.reason));
                    }
                    let conf = if mgmt_failed { Confidence::High } else { Confidence::Medium };
                    (
                        HypKind::ApUnavailable,
                        format!("{ap} or its uplink/power is unavailable"),
                        conf,
                        vec!["switch port / PoE failure".into(), "AP reboot or firmware fault".into()],
                        "check the AP's switch port, PoE budget and uplink".into(),
                    )
                };
                absorbed_nodes.extend(affected.iter().cloned());
                out.push(Hypothesis {
                    key: format!("ap:{ap}"),
                    kind,
                    severity: sev_for_asset(cfg, ap, Severity::Warning),
                    title: match kind {
                        HypKind::ApRadioIssue => format!("{ap} radio unavailable"),
                        _ => format!("{ap} or uplink unavailable"),
                    },
                    cause,
                    confidence,
                    scope_assets: vec![ap.to_string()],
                    affected_nodes: affected.into_iter().collect(),
                    evidence,
                    contradicting,
                    alternatives: alts,
                    next_check: next,
                });
            }
        }

        // R3: individual missing nodes not explained above (S04).
        for n in s.nodes.iter().filter(|n| n.liveness == NodeLiveness::Missing && !absorbed_nodes.contains(&n.id)) {
            let peers_ok = s.nodes.iter().filter(|o| o.id != n.id && o.liveness == NodeLiveness::Online).count();
            out.push(Hypothesis {
                key: format!("node:{}", n.id),
                kind: HypKind::NodeMissing,
                severity: Severity::Warning,
                title: format!("Node {} not reporting", n.id),
                cause: "unknown cause: node power, firmware or local RF problem".into(),
                confidence: Confidence::Low,
                scope_assets: n.ap.iter().cloned().collect(),
                affected_nodes: vec![n.id.clone()],
                evidence: vec![format!("no fresh telemetry from {} for > {} s", n.id, cfg.thresholds.node_missing_ms / 1000)],
                contradicting: if peers_ok > 0 { vec![format!("{peers_ok} other node(s) reporting normally")] } else { vec![] },
                alternatives: vec!["USB power removed".into(), "Wi-Fi association failure".into(), "firmware crash/watchdog".into()],
                next_check: "check the node's power/USB and its serial log; outlet failure is not confirmed by absence alone".into(),
            });
        }
    }

    // Targets observed from vantages that are still trustworthy.
    let live_vantage = |v: &str| -> bool {
        v == CENTRAL
            || (s.ingestion_ok && !absorbed_nodes.contains(v) && s.nodes.iter().any(|n| n.id == v && n.liveness != NodeLiveness::Missing))
    };
    let tv: Vec<&TargetView> = s.targets.iter().filter(|t| live_vantage(&t.vantage)).collect();
    let bad = |t: &&TargetView| t.health.is_bad();

    // R4: WAN outage: gateway reachable, >= 2 independent external checks failing (S08).
    let wan_bad: Vec<&TargetView> = tv
        .iter()
        .copied()
        .filter(|t| asset_kind(cfg, t.asset.as_deref()) == Some(AssetKind::Wan) && t.health == Health::Failed)
        .collect();
    let gw_ok = tv
        .iter()
        .any(|t| asset_kind(cfg, t.asset.as_deref()) == Some(AssetKind::Router) && t.health == Health::Healthy);
    let distinct_wan: BTreeSet<&str> = wan_bad.iter().map(|t| t.target_id.as_str()).collect();
    if distinct_wan.len() >= 2 && gw_ok {
        out.push(Hypothesis {
            key: "wan".into(),
            kind: HypKind::WanOutage,
            severity: Severity::Critical,
            title: "WAN / upstream connectivity outage".into(),
            cause: "local gateway reachable but multiple independent external checks fail".into(),
            confidence: Confidence::High,
            scope_assets: wan_bad.iter().filter_map(|t| t.asset.clone()).collect::<BTreeSet<_>>().into_iter().collect(),
            affected_nodes: vec![],
            evidence: wan_bad.iter().map(|t| format!("{} from {}: {}", t.target_id, t.vantage, t.reason)).collect(),
            contradicting: vec!["local gateway checks healthy".into()],
            alternatives: vec!["upstream DNS failure".into(), "ISP routing issue".into()],
            next_check: "check OPNsense WAN gateway status (dpinger) and ISP modem".into(),
        });
    } else if distinct_wan.len() == 1 {
        let t = wan_bad.first().copied();
        if let Some(t) = t {
            out.push(Hypothesis {
                key: format!("service:{}", t.target_id),
                kind: HypKind::ServiceFailure,
                severity: Severity::Warning,
                title: format!("External check {} failing", t.target_id),
                cause: "single external endpoint failure; not enough evidence for a WAN outage".into(),
                confidence: Confidence::Low,
                scope_assets: t.asset.iter().cloned().collect(),
                affected_nodes: vec![],
                evidence: vec![format!("{}: {}", t.target_id, t.reason)],
                contradicting: vec![],
                alternatives: vec!["remote service outage".into()],
                next_check: "configure a second independent external check".into(),
            });
        }
    }
    let wan_claimed = distinct_wan.len() >= 2 && gw_ok;

    // R5: DNS (S05 / S06).
    let dns: Vec<&TargetView> = tv.iter().copied().filter(|t| t.kind == "dns").collect();
    let dns_bad: Vec<&TargetView> = dns.iter().copied().filter(bad).collect();
    let ip_ok = |vantage: &str| {
        tv.iter().any(|t| t.vantage == vantage && (t.kind == "icmp" || t.kind == "udp_echo") && t.health == Health::Healthy)
    };
    if !dns_bad.is_empty() && !wan_claimed {
        let wired_dns_bad = dns_bad.iter().any(|t| is_wired(t));
        let wired_dns_ok = dns.iter().any(|t| is_wired(t) && t.health == Health::Healthy);
        let vantages: BTreeSet<&str> = dns_bad.iter().map(|t| t.vantage.as_str()).collect();
        let ip_fine = vantages.iter().all(|v| ip_ok(v));
        let evidence: Vec<String> =
            dns_bad.iter().map(|t| format!("{} from {}: {}", t.target_id, t.vantage, t.reason)).collect();
        if wired_dns_bad || (vantages.len() >= 2 && !wired_dns_ok) {
            out.push(Hypothesis {
                key: "dns:resolver".into(),
                kind: HypKind::DnsResolver,
                severity: if dns_bad.iter().any(|t| t.critical) { Severity::Critical } else { Severity::Warning },
                title: "DNS resolution failing".into(),
                cause: if ip_fine {
                    "resolver or upstream DNS failure; IP reachability is healthy".into()
                } else {
                    "DNS failing; IP reachability also impaired from some vantages".into()
                },
                confidence: if ip_fine { Confidence::High } else { Confidence::Medium },
                scope_assets: dns_bad.iter().filter_map(|t| t.asset.clone()).collect::<BTreeSet<_>>().into_iter().collect(),
                affected_nodes: vec![],
                evidence,
                contradicting: if ip_fine { vec!["ICMP/UDP probes to the same vantages succeed".into()] } else { vec![] },
                alternatives: vec!["upstream forwarder outage".into(), "local zone misconfiguration".into()],
                next_check: "compare local-record vs uncached profiles; inspect Unbound status".into(),
            });
        } else if wired_dns_ok && (vantages.len() >= 2 || dns_bad.iter().any(|t| t.health == Health::Failed)) {
            out.push(Hypothesis {
                key: "dns:client-path".into(),
                kind: HypKind::DnsClientPath,
                severity: Severity::Warning,
                title: "DNS failing from wireless clients only".into(),
                cause: "client path / RF / QoS issue between wireless vantages and the resolver".into(),
                confidence: Confidence::Medium,
                scope_assets: vec![],
                affected_nodes: vantages.iter().map(|v| v.to_string()).collect(),
                evidence,
                contradicting: vec!["wired DNS check of the same resolver is healthy".into()],
                alternatives: vec!["UDP loss on Wi-Fi".into(), "resolver rate limiting of wireless clients".into()],
                next_check: "compare gateway RTT/loss on the same vantages and UDP vs TCP DNS".into(),
            });
        } else if !wired_dns_ok && (vantages.len() >= 2 || dns_bad.iter().any(|t| t.health == Health::Failed)) {
            out.push(Hypothesis {
                key: "dns:unknown".into(),
                kind: HypKind::UnknownDegradation,
                severity: Severity::Warning,
                title: "DNS failures (cause unknown)".into(),
                cause: "unknown cause: only one vantage and no wired DNS baseline".into(),
                confidence: Confidence::Low,
                scope_assets: vec![],
                affected_nodes: vantages.iter().map(|v| v.to_string()).collect(),
                evidence,
                contradicting: vec![],
                alternatives: vec![],
                next_check: "add a central DNS check against the same resolver".into(),
            });
        }
    }

    // R6: latency/loss on IP paths (S07).
    let ip_bad_wireless: Vec<&TargetView> = tv
        .iter()
        .copied()
        .filter(|t| !is_wired(t) && (t.kind == "icmp" || t.kind == "udp_echo") && t.health == Health::Degraded)
        .collect();
    // Corroboration: >= 2 vantages, or >= 2 degraded targets at one vantage. A single
    // marginal target at one node (likely chance at fleet scale) stays visible as
    // degraded target health but does not open an incident.
    let bad_vantages: BTreeSet<&str> = ip_bad_wireless.iter().map(|t| t.vantage.as_str()).collect();
    let corroborated = bad_vantages.len() >= 2 || ip_bad_wireless.len() >= 2;
    if corroborated {
        let wired: Vec<&TargetView> =
            tv.iter().copied().filter(|t| is_wired(t) && (t.kind == "icmp" || t.kind == "tcp")).collect();
        let wired_bad = wired.iter().any(|t| t.health.is_bad());
        let wired_ok = !wired.is_empty() && wired.iter().all(|t| t.health == Health::Healthy);
        let evidence: Vec<String> =
            ip_bad_wireless.iter().map(|t| format!("{} from {}: {}", t.target_id, t.vantage, t.reason)).collect();
        let vantages: Vec<String> =
            ip_bad_wireless.iter().map(|t| t.vantage.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let (key, kind, title, cause, conf, contra, next) = if wired_bad {
            (
                "lan:congestion",
                HypKind::SharedLanCongestion,
                "Shared LAN/router congestion",
                "wired and wireless paths both degraded",
                Confidence::Medium,
                vec![],
                "compare router/switch interface utilization and queue drops",
            )
        } else if wired_ok {
            (
                "rf:degraded",
                HypKind::WirelessPathDegraded,
                "Wireless path degraded",
                "RF contention, coverage or AP path (wired baseline healthy)",
                Confidence::Medium,
                vec!["wired central baseline healthy".to_string()],
                "check AP retries/channel utilization and scan overlap flags",
            )
        } else {
            (
                "net:unknown",
                HypKind::UnknownDegradation,
                "Network degradation (cause unknown)",
                "unknown cause: no wired baseline to compare",
                Confidence::Low,
                vec![],
                "configure central checks to the same gateway/server",
            )
        };
        out.push(Hypothesis {
            key: key.into(),
            kind,
            severity: Severity::Warning,
            title: title.into(),
            cause: cause.into(),
            confidence: conf,
            scope_assets: vec![],
            affected_nodes: vantages,
            evidence,
            contradicting: contra,
            alternatives: vec!["deliberate test traffic".into()],
            next_check: next.into(),
        });
    }

    // R7: critical wired asset unreachable / single service failure.
    let claimed: BTreeSet<String> = out.iter().flat_map(|h| h.scope_assets.clone()).collect();
    for t in tv.iter().filter(|t| is_wired(t) && t.health == Health::Failed) {
        let Some(asset) = t.asset.clone() else { continue };
        if claimed.contains(&asset) || asset_kind(cfg, Some(&asset)) == Some(AssetKind::Wan) {
            continue;
        }
        if t.kind == "dns" {
            continue; // handled by DNS rule
        }
        let others_ok = tv.iter().any(|o| is_wired(o) && o.asset.as_deref() != Some(asset.as_str()) && o.health == Health::Healthy);
        let corroborated: Vec<&&TargetView> = tv
            .iter()
            .filter(|o| !is_wired(o) && o.asset.as_deref() == Some(asset.as_str()) && o.health == Health::Failed)
            .collect();
        let service = matches!(t.kind.as_str(), "http" | "tcp");
        let kind = if service && others_ok { HypKind::ServiceFailure } else { HypKind::AssetUnreachable };
        let key = format!("asset:{asset}");
        if out.iter().any(|h| h.key == key) {
            continue;
        }
        out.push(Hypothesis {
            key,
            kind,
            severity: sev_for_asset(cfg, &asset, Severity::Warning),
            title: if kind == HypKind::ServiceFailure {
                format!("Service {asset} unhealthy")
            } else {
                format!("{asset} unreachable")
            },
            cause: if kind == HypKind::ServiceFailure {
                "application/service-specific failure; network and other services healthy".into()
            } else {
                format!("{asset} not responding to wired checks")
            },
            confidence: if !corroborated.is_empty() { Confidence::High } else { Confidence::Medium },
            scope_assets: vec![asset.clone()],
            affected_nodes: vec![],
            evidence: std::iter::once(format!("{} (wired): {}", t.target_id, t.reason))
                .chain(corroborated.iter().map(|o| format!("{} from {}: {}", o.target_id, o.vantage, o.reason)))
                .collect(),
            contradicting: if others_ok { vec!["other wired checks healthy".into()] } else { vec![] },
            alternatives: vec!["ICMP rate limiting/blocking (corroborate with a service check)".into()],
            next_check: "check the asset's power, link and service status".into(),
        });
    }

    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

// ------------------------------------------------------------------ lifecycle

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Recovering,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentEventKind {
    Opened,
    Updated,
    Escalated,
    Recovering,
    Resolved,
    Reopened,
}

impl IncidentEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Updated => "updated",
            Self::Escalated => "escalated",
            Self::Recovering => "recovering",
            Self::Resolved => "resolved",
            Self::Reopened => "reopened",
        }
    }
    /// Whether this lifecycle step warrants an outbound notification.
    pub fn notifies(self) -> bool {
        matches!(self, Self::Opened | Self::Escalated | Self::Resolved | Self::Reopened)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub key: String,
    pub status: IncidentStatus,
    pub severity: Severity,
    pub episode: u32,
    pub flaps: u32,
    pub opened_at: UnixMs,
    pub last_evidence_at: UnixMs,
    pub recovering_since: Option<UnixMs>,
    pub resolved_at: Option<UnixMs>,
    pub hypothesis: Hypothesis,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub incident_id: String,
    pub key: String,
    pub kind: IncidentEventKind,
    pub episode: u32,
    pub severity: Severity,
    pub at: UnixMs,
    pub title: String,
    pub summary: String,
}

#[derive(Debug, Clone, Default)]
pub struct IncidentManager {
    pub incidents: BTreeMap<String, Incident>,
    counter: u64,
}

impl IncidentManager {
    /// Restore the id counter after a restart (ids stay unique and stable).
    pub fn with_counter(counter: u64) -> Self {
        Self { incidents: BTreeMap::new(), counter }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    fn event(inc: &Incident, kind: IncidentEventKind, now: UnixMs) -> IncidentEvent {
        IncidentEvent {
            incident_id: inc.id.clone(),
            key: inc.key.clone(),
            kind,
            episode: inc.episode,
            severity: inc.severity,
            at: now,
            title: inc.hypothesis.title.clone(),
            summary: inc.hypothesis.cause.clone(),
        }
    }

    /// Reconcile the current hypotheses with open incidents.
    pub fn reconcile(&mut self, hyps: Vec<Hypothesis>, now: UnixMs, th: &Thresholds) -> Vec<IncidentEvent> {
        let mut events = Vec::new();
        let present: BTreeSet<String> = hyps.iter().map(|h| h.key.clone()).collect();
        for h in hyps {
            match self.incidents.get_mut(&h.key) {
                Some(inc) if inc.status == IncidentStatus::Open => {
                    let escalated = h.severity > inc.severity || h.affected_nodes.len() > inc.hypothesis.affected_nodes.len();
                    let changed = h.kind != inc.hypothesis.kind || h.cause != inc.hypothesis.cause;
                    inc.severity = inc.severity.max(h.severity);
                    inc.last_evidence_at = now;
                    inc.hypothesis = h;
                    if escalated {
                        events.push(Self::event(inc, IncidentEventKind::Escalated, now));
                    } else if changed {
                        events.push(Self::event(inc, IncidentEventKind::Updated, now));
                    }
                }
                Some(inc) if inc.status == IncidentStatus::Recovering => {
                    inc.status = IncidentStatus::Open;
                    inc.flaps += 1;
                    inc.episode += 1;
                    inc.recovering_since = None;
                    inc.last_evidence_at = now;
                    inc.severity = h.severity;
                    inc.hypothesis = h;
                    events.push(Self::event(inc, IncidentEventKind::Reopened, now));
                }
                Some(inc)
                    if inc.status == IncidentStatus::Resolved
                        && inc.resolved_at.is_some_and(|r| now - r <= th.recurrence_window_ms) =>
                {
                    inc.status = IncidentStatus::Open;
                    inc.flaps += 1;
                    inc.episode += 1;
                    inc.resolved_at = None;
                    inc.last_evidence_at = now;
                    inc.severity = h.severity;
                    inc.hypothesis = h;
                    inc.acknowledged = false;
                    events.push(Self::event(inc, IncidentEventKind::Reopened, now));
                }
                _ => {
                    self.counter += 1;
                    let inc = Incident {
                        id: format!("inc-{:06}", self.counter),
                        key: h.key.clone(),
                        status: IncidentStatus::Open,
                        severity: h.severity,
                        episode: 1,
                        flaps: 0,
                        opened_at: now,
                        last_evidence_at: now,
                        recovering_since: None,
                        resolved_at: None,
                        hypothesis: h,
                        acknowledged: false,
                    };
                    events.push(Self::event(&inc, IncidentEventKind::Opened, now));
                    self.incidents.insert(inc.key.clone(), inc);
                }
            }
        }
        for inc in self.incidents.values_mut() {
            if present.contains(&inc.key) {
                continue;
            }
            match inc.status {
                IncidentStatus::Open => {
                    inc.status = IncidentStatus::Recovering;
                    inc.recovering_since = Some(now);
                    events.push(Self::event(inc, IncidentEventKind::Recovering, now));
                }
                IncidentStatus::Recovering if inc.recovering_since.is_some_and(|t| now - t >= th.recovery_stable_ms) => {
                    inc.status = IncidentStatus::Resolved;
                    inc.resolved_at = Some(now);
                    inc.recovering_since = None;
                    events.push(Self::event(inc, IncidentEventKind::Resolved, now));
                }
                _ => {}
            }
        }
        events
    }

    pub fn active(&self) -> impl Iterator<Item = &Incident> {
        self.incidents.values().filter(|i| i.status != IncidentStatus::Resolved)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg() -> SiteConfig {
        SiteConfig::from_yaml_str(
            r#"
schema_version: 1
site_id: home
nodes: [{id: n1}, {id: n2}, {id: n3}, {id: n4}]
assets:
  - {id: gateway, kind: router, critical: true}
  - {id: ap-a, kind: access_point, critical: true, parents: [gateway]}
  - {id: ap-b, kind: access_point, parents: [gateway]}
  - {id: wan-1, kind: wan}
  - {id: wan-2, kind: wan}
"#,
        )
        .unwrap()
    }

    fn node(id: &str, l: NodeLiveness, ap: &str) -> NodeView {
        NodeView { id: id.into(), liveness: l, ap: Some(ap.into()) }
    }

    fn tgt(v: &str, id: &str, kind: &str, asset: &str, h: Health) -> TargetView {
        TargetView {
            vantage: v.into(),
            target_id: id.into(),
            kind: kind.into(),
            asset: Some(asset.into()),
            critical: true,
            health: h,
            reason: "test".into(),
        }
    }

    #[test]
    fn ap_outage_groups_missing_and_roamed_nodes() {
        let c = cfg();
        let nodes = [
            node("n1", NodeLiveness::Missing, "ap-a"),
            node("n2", NodeLiveness::Online, "ap-b"),
            node("n3", NodeLiveness::Online, "ap-b"),
            node("n4", NodeLiveness::Online, "ap-b"),
        ];
        let roams = [
            RoamView { node: "n2".into(), from_ap: "ap-a".into(), to_ap: Some("ap-b".into()), at: 1000 },
            RoamView { node: "n3".into(), from_ap: "ap-a".into(), to_ap: Some("ap-b".into()), at: 1000 },
        ];
        let targets = [tgt(CENTRAL, "ap-a-mgmt", "icmp", "ap-a", Health::Failed)];
        let s = Snapshot { config: &c, now: 2000, ingestion_ok: true, nodes: &nodes, targets: &targets, roams: &roams, radios: &[] };
        let h = correlate(&s);
        assert_eq!(h.len(), 1, "{h:#?}");
        assert_eq!(h[0].kind, HypKind::ApUnavailable);
        assert_eq!(h[0].affected_nodes, vec!["n1", "n2", "n3"]);
        assert_eq!(h[0].confidence, Confidence::High);
        assert_eq!(h[0].severity, Severity::Critical);
    }

    #[test]
    fn ingestion_down_suppresses_node_claims() {
        let c = cfg();
        let nodes = [node("n1", NodeLiveness::Unknown, "ap-a")];
        let s = Snapshot { config: &c, now: 0, ingestion_ok: false, nodes: &nodes, targets: &[], roams: &[], radios: &[] };
        let h = correlate(&s);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].kind, HypKind::ObservabilityOutage);
    }

    #[test]
    fn single_wan_failure_is_not_a_wan_outage() {
        let c = cfg();
        let targets = [
            tgt(CENTRAL, "gw", "icmp", "gateway", Health::Healthy),
            tgt(CENTRAL, "ext1", "http", "wan-1", Health::Failed),
        ];
        let s = Snapshot { config: &c, now: 0, ingestion_ok: true, nodes: &[], targets: &targets, roams: &[], radios: &[] };
        let h = correlate(&s);
        assert!(h.iter().all(|x| x.kind != HypKind::WanOutage));
    }

    #[test]
    fn lifecycle_open_recover_resolve_and_reopen_episode() {
        let th = Thresholds::default();
        let mut m = IncidentManager::default();
        let h = Hypothesis {
            key: "node:n1".into(),
            kind: HypKind::NodeMissing,
            severity: Severity::Warning,
            title: "t".into(),
            cause: "c".into(),
            confidence: Confidence::Low,
            scope_assets: vec![],
            affected_nodes: vec!["n1".into()],
            evidence: vec![],
            contradicting: vec![],
            alternatives: vec![],
            next_check: String::new(),
        };
        let e = m.reconcile(vec![h.clone()], 0, &th);
        assert_eq!(e[0].kind, IncidentEventKind::Opened);
        assert!(m.reconcile(vec![h.clone()], 1000, &th).is_empty(), "no duplicate events");
        assert_eq!(m.reconcile(vec![], 2000, &th)[0].kind, IncidentEventKind::Recovering);
        assert!(m.reconcile(vec![], 5000, &th).is_empty());
        assert_eq!(m.reconcile(vec![], 2000 + th.recovery_stable_ms, &th)[0].kind, IncidentEventKind::Resolved);
        let e = m.reconcile(vec![h.clone()], 60_000, &th);
        assert_eq!(e[0].kind, IncidentEventKind::Reopened);
        assert_eq!(e[0].episode, 2);
        assert_eq!(e[0].incident_id, "inc-000001", "same incident within recurrence window");
        m.reconcile(vec![], 70_000, &th);
        m.reconcile(vec![], 70_000 + th.recovery_stable_ms, &th);
        let e = m.reconcile(vec![h], 70_000 + th.recovery_stable_ms + th.recurrence_window_ms + 1, &th);
        assert_eq!(e[0].kind, IncidentEventKind::Opened);
        assert_eq!(e[0].incident_id, "inc-000002");
    }
}
