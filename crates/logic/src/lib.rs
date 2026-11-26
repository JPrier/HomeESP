//! Pure domain logic. Nothing here performs IO, reads clocks, uses global mutable
//! state or loads configuration implicitly: time, configuration and observations are
//! always passed in, so every reducer is deterministic and replayable.

pub mod engine;
pub mod health;
pub mod incidents;
pub mod location;
pub mod normalize;
pub mod recommend;
pub mod seq;
pub mod stats;
pub mod timesync;

pub use engine::{Effect, Engine, EngineSnapshot, Input};
