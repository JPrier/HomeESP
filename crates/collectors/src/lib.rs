//! Central (wired) collectors and read-only infrastructure adapters.
//!
//! Every collector produces the same normalized `ProbeObs` the nodes produce, with
//! vantage `central`. Collectors only ever contact targets listed in the site config
//! (no discovery, no scanning) and each has its own timeout.

pub mod dns;
pub mod echo;
pub mod opnsense;
pub mod probes;
pub mod snmp;

pub use probes::{run_check, CheckResult};
