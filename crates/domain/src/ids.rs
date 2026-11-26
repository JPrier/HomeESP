//! Validated identifiers. Stable IDs are separate from display names and addresses.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Error for an identifier that violates the `[a-z0-9-]{1,32}` rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid identifier {0:?}: use 1-32 chars of [a-z0-9-], not starting/ending with '-'")]
pub struct InvalidId(pub String);

/// Shared validation for every ID type.
pub fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Parse and validate.
            pub fn new(s: impl Into<String>) -> Result<Self, InvalidId> {
                let s = s.into();
                if valid_id(&s) { Ok(Self(s)) } else { Err(InvalidId(s)) }
            }
            /// Borrow as `&str`.
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl TryFrom<String> for $name {
            type Error = InvalidId;
            fn try_from(s: String) -> Result<Self, InvalidId> { Self::new(s) }
        }
        impl From<$name> for String {
            fn from(v: $name) -> String { v.0 }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str { &self.0 }
        }
    };
}

id_type!(
    /// Sensor node identifier (also its MQTT username).
    NodeId
);
id_type!(
    /// Site identifier (MQTT namespace segment).
    SiteId
);
id_type!(
    /// Infrastructure asset identifier (router, AP, switch, service...).
    AssetId
);
id_type!(
    /// Room identifier.
    RoomId
);
id_type!(
    /// Enrolled device identifier (opaque; never a MAC address).
    DeviceId
);
id_type!(
    /// Probe target identifier.
    TargetId
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn id_rules() {
        assert!(NodeId::new("node-01").is_ok());
        for bad in ["", "Node", "-a", "a-", "a_b", "a b", &"x".repeat(33)] {
            assert!(NodeId::new(bad).is_err(), "{bad:?}");
        }
        let id: NodeId = serde_yaml::from_str("node-02").unwrap();
        assert_eq!(id.as_str(), "node-02");
        assert!(serde_yaml::from_str::<NodeId>("Bad").is_err());
    }
}
