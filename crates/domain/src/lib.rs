//! Domain types shared by every layer: identifiers, site configuration (schema +
//! validation), normalized observations and derived-state vocabularies.
//!
//! This crate performs no IO except the explicit `SiteConfig::from_yaml_str` parse
//! helper (pure string -> value). Loading files is the caller's job.

pub mod config;
pub mod ids;
pub mod model;

pub use config::*;
pub use ids::*;
pub use model::*;

/// Milliseconds since the Unix epoch (UTC). The only wall-clock unit in the domain.
pub type UnixMs = i64;
