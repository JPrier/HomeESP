//! Read-only OPNsense API adapter (spec §11.3). Uses a least-privilege API key over
//! HTTPS with certificate validation; only GET endpoints are called. Missing or
//! forbidden data is reported as `unknown`, never as zero.
//!
//! Compatibility: endpoint shapes are taken from OPNsense's documented API
//! (`/api/routes/gateway/status`, `/api/unbound/diagnostics/stats`). The parsers are
//! tested against representative fixtures only; live verification against the
//! deployed version is recorded in docs/compatibility.md (NOT RUN until configured).

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayStatus {
    pub name: String,
    pub status: String,
    /// dpinger round-trip in ms, if reported.
    pub delay_ms: Option<f64>,
    pub stddev_ms: Option<f64>,
    pub loss_pct: Option<f64>,
}

fn parse_unit(v: &serde_json::Value) -> Option<f64> {
    // OPNsense reports values like "12.3 ms" / "0.0 %" / "~".
    let s = v.as_str()?;
    let num: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
    num.parse().ok()
}

/// Parse `/api/routes/gateway/status`.
pub fn parse_gateways(body: &str) -> Result<Vec<GatewayStatus>, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let items = v.get("items").and_then(|i| i.as_array()).ok_or("missing items")?;
    Ok(items
        .iter()
        .take(64)
        .filter_map(|it| {
            Some(GatewayStatus {
                name: it.get("name")?.as_str()?.chars().take(64).collect(),
                status: it.get("status").and_then(|s| s.as_str()).unwrap_or("unknown").chars().take(32).collect(),
                delay_ms: it.get("delay").and_then(parse_unit),
                stddev_ms: it.get("stddev").and_then(parse_unit),
                loss_pct: it.get("loss").and_then(parse_unit),
            })
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct UnboundStats {
    pub queries: Option<u64>,
    pub cache_hits: Option<u64>,
    pub cache_misses: Option<u64>,
    pub servfail: Option<u64>,
    pub recursion_avg_s: Option<f64>,
}

/// Parse `/api/unbound/diagnostics/stats` (nested `data.total.*` / `data.num.answer.rcode.*`).
pub fn parse_unbound(body: &str) -> Result<UnboundStats, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let d = v.get("data").ok_or("missing data")?;
    let n = |p: &[&str]| -> Option<u64> {
        let mut cur = d;
        for k in p {
            cur = cur.get(*k)?;
        }
        cur.as_str().and_then(|s| s.parse().ok()).or_else(|| cur.as_u64())
    };
    let f = |p: &[&str]| -> Option<f64> {
        let mut cur = d;
        for k in p {
            cur = cur.get(*k)?;
        }
        cur.as_str().and_then(|s| s.parse().ok()).or_else(|| cur.as_f64())
    };
    Ok(UnboundStats {
        queries: n(&["total", "num", "queries"]),
        cache_hits: n(&["total", "num", "cachehits"]),
        cache_misses: n(&["total", "num", "cachemiss"]),
        servfail: n(&["num", "answer", "rcode", "SERVFAIL"]),
        recursion_avg_s: f(&["total", "recursion", "time", "avg"]),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum FetchError {
    /// 401/403: credentials lack privilege. Data is unknown, not zero.
    Forbidden,
    /// 404: endpoint/module not present in this version.
    NotAvailable,
    Transport(String),
    Parse(String),
}

/// Minimal read-only client.
pub struct OpnsenseClient {
    base: String,
    key: String,
    secret: String,
    http: reqwest::Client,
}

impl OpnsenseClient {
    pub fn new(base_url: &str, key: String, secret: String, timeout: Duration) -> Result<Self, String> {
        if !base_url.starts_with("https://") {
            return Err("OPNsense base_url must be https".into());
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { base: base_url.trim_end_matches('/').into(), key, secret, http })
    }

    async fn get(&self, path: &str) -> Result<String, FetchError> {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .basic_auth(&self.key, Some(&self.secret))
            .send()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        match r.status().as_u16() {
            200 => {}
            401 | 403 => return Err(FetchError::Forbidden),
            404 => return Err(FetchError::NotAvailable),
            s => return Err(FetchError::Transport(format!("HTTP {s}"))),
        }
        let bytes = r.bytes().await.map_err(|e| FetchError::Transport(e.to_string()))?;
        if bytes.len() > 1_000_000 {
            return Err(FetchError::Parse("response too large".into()));
        }
        String::from_utf8(bytes.to_vec()).map_err(|e| FetchError::Parse(e.to_string()))
    }

    pub async fn gateways(&self) -> Result<Vec<GatewayStatus>, FetchError> {
        parse_gateways(&self.get("/api/routes/gateway/status").await?).map_err(FetchError::Parse)
    }

    pub async fn unbound(&self) -> Result<UnboundStats, FetchError> {
        parse_unbound(&self.get("/api/unbound/diagnostics/stats").await?).map_err(FetchError::Parse)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const GW: &str = include_str!("../../../tests/fixtures/opnsense/gateway_status.json");
    const UB: &str = include_str!("../../../tests/fixtures/opnsense/unbound_stats.json");

    #[test]
    fn parses_gateway_fixture() {
        let g = parse_gateways(GW).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].name, "WAN_DHCP");
        assert_eq!(g[0].delay_ms, Some(11.2));
        assert_eq!(g[0].loss_pct, Some(0.0));
        assert_eq!(g[1].delay_ms, None, "'~' means unknown, not zero");
    }

    #[test]
    fn parses_unbound_fixture_and_tolerates_missing() {
        let u = parse_unbound(UB).unwrap();
        assert_eq!(u.queries, Some(12345));
        assert_eq!(u.servfail, Some(3));
        let partial = parse_unbound(r#"{"data":{}}"#).unwrap();
        assert_eq!(partial.queries, None);
        assert!(parse_unbound("not json").is_err());
    }

    #[test]
    fn refuses_plain_http() {
        assert!(OpnsenseClient::new("http://router", String::new(), String::new(), Duration::from_secs(1)).is_err());
    }
}
