//! Notification delivery: ntfy and authenticated webhook, with explicit transient vs
//! permanent failure classification so the outbox can retry with capped backoff.
//! Delivery is at-least-once; the outbox dedup key prevents duplicate enqueueing.

use ho_domain::{NotifierConf, NotifierKind, Severity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub incident_id: String,
    pub event: String,
    pub episode: u32,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    pub at: i64,
    #[serde(default)]
    pub test: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryError {
    /// Retry later (timeouts, 5xx, 429).
    Transient(String),
    /// Will never succeed as configured (4xx other than 429, bad URL).
    Permanent(String),
}

/// Capped exponential backoff: 10 s, 20 s, 40 s ... up to 15 min.
pub fn backoff_ms(attempts: i64) -> i64 {
    let a = attempts.clamp(0, 16) as u32;
    (10_000i64.saturating_mul(1i64 << a.min(7))).min(900_000)
}

/// Maximum attempts before an item is marked failed.
pub const MAX_ATTEMPTS: i64 = 12;

pub fn classify_status(status: u16) -> Result<(), DeliveryError> {
    match status {
        200..=299 => Ok(()),
        429 | 500..=599 => Err(DeliveryError::Transient(format!("HTTP {status}"))),
        s => Err(DeliveryError::Permanent(format!("HTTP {s}"))),
    }
}

fn priority(s: Severity, event: &str) -> &'static str {
    if event == "resolved" {
        return "default";
    }
    match s {
        Severity::Critical => "urgent",
        Severity::Warning => "high",
        Severity::Info => "default",
    }
}

/// Deliver one message. `token` is read from the notifier's token file by the caller.
pub async fn deliver(
    n: &NotifierConf,
    token: Option<&str>,
    m: &Message,
) -> Result<(), DeliveryError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(n.timeout_ms.clamp(500, 30_000)))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| DeliveryError::Permanent(e.to_string()))?;
    let title = if m.test {
        format!("[TEST] {}", m.title)
    } else {
        m.title.clone()
    };
    let req = match n.kind {
        NotifierKind::Ntfy => {
            let mut r = client
                .post(&n.url)
                .header("Title", sanitize_header(&title))
                .header("Priority", priority(m.severity, &m.event))
                .header(
                    "Tags",
                    if m.event == "resolved" {
                        "white_check_mark"
                    } else {
                        "warning"
                    },
                )
                .body(m.body.clone());
            if let Some(t) = token {
                r = r.bearer_auth(t);
            }
            r
        }
        NotifierKind::Webhook => {
            let mut r = client.post(&n.url).json(m);
            if let Some(t) = token {
                r = r.bearer_auth(t);
            }
            r
        }
    };
    match req.send().await {
        Ok(resp) => classify_status(resp.status().as_u16()),
        Err(e) if e.is_timeout() || e.is_connect() => Err(DeliveryError::Transient(e.to_string())),
        Err(e) if e.is_builder() => Err(DeliveryError::Permanent(e.to_string())),
        Err(e) => Err(DeliveryError::Transient(e.to_string())),
    }
}

fn sanitize_header(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .take(200)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn backoff_is_capped_and_monotonic() {
        let v: Vec<i64> = (0..20).map(backoff_ms).collect();
        assert!(v.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(*v.last().unwrap(), 900_000);
        assert_eq!(v[0], 10_000);
    }

    #[test]
    fn status_classification() {
        assert!(classify_status(204).is_ok());
        assert!(matches!(
            classify_status(429),
            Err(DeliveryError::Transient(_))
        ));
        assert!(matches!(
            classify_status(503),
            Err(DeliveryError::Transient(_))
        ));
        assert!(matches!(
            classify_status(403),
            Err(DeliveryError::Permanent(_))
        ));
    }

    async fn one_shot_server(status: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/topic", l.local_addr().unwrap());
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        (url, h)
    }

    fn msg() -> Message {
        Message {
            incident_id: "inc-1".into(),
            event: "opened".into(),
            episode: 1,
            severity: Severity::Critical,
            title: "AP down".into(),
            body: "evidence".into(),
            at: 0,
            test: true,
        }
    }

    #[tokio::test]
    async fn ntfy_delivery_sets_headers_and_auth() {
        let (url, h) = one_shot_server("200 OK").await;
        let n = NotifierConf {
            id: "n".into(),
            kind: NotifierKind::Ntfy,
            url,
            token_file: None,
            allow_plain_http_lan: true,
            timeout_ms: 2000,
        };
        deliver(&n, Some("secret-token"), &msg()).await.unwrap();
        let req = h.await.unwrap().to_lowercase();
        assert!(req.contains("title: [test] ap down"), "{req}");
        assert!(req.contains("authorization: bearer secret-token"));
        assert!(req.contains("priority: urgent"));
    }

    #[tokio::test]
    async fn webhook_failure_is_classified() {
        let (url, h) = one_shot_server("500 Internal Server Error").await;
        let n = NotifierConf {
            id: "w".into(),
            kind: NotifierKind::Webhook,
            url,
            token_file: None,
            allow_plain_http_lan: true,
            timeout_ms: 2000,
        };
        assert!(matches!(
            deliver(&n, None, &msg()).await,
            Err(DeliveryError::Transient(_))
        ));
        let body = h.await.unwrap();
        assert!(body.contains("\"incident_id\":\"inc-1\""));
        // Unreachable endpoint -> transient, never "delivered".
        let n2 = NotifierConf {
            url: "http://127.0.0.1:9/x".into(),
            ..n
        };
        assert!(deliver(&n2, None, &msg()).await.is_err());
    }
}
