//! External watchdog heartbeat client (spec §14.2). Sends a minimal HTTPS ping to an
//! independently hosted monitor; no telemetry leaves the site. The *external* service
//! raises the alert when pings stop (total site/WAN/power loss).

use std::time::Duration;

/// Send one heartbeat. Returns Ok only on a 2xx response.
pub async fn ping(url: &str, timeout: Duration) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("watchdog url must be https".into());
    }
    let c = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let r = c.get(url).send().await.map_err(|e| e.to_string())?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", r.status().as_u16()))
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn refuses_plain_http() {
        assert!(super::ping(
            "http://example.invalid",
            std::time::Duration::from_millis(10)
        )
        .await
        .is_err());
    }
}
