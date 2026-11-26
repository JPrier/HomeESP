//! Outbound integrations: Home Assistant MQTT discovery, notifiers, Prometheus
//! exposition and the external watchdog heartbeat. Payload builders are pure; the
//! server performs the actual publish/HTTP calls.

pub mod ha;
pub mod metrics;
pub mod notify;
pub mod watchdog;
