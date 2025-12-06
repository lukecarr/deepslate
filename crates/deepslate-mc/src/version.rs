//! Protocol version definitions.
//!
//! This module provides the [`ProtocolVersion`] enum for identifying
//! which Minecraft protocol version a client is using.

/// Minecraft protocol version.
///
/// Each variant represents a specific protocol version number.
/// Variants are feature-gated to allow compile-time selection of
/// supported versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// Protocol version 773 (Minecraft 1.21.9/1.21.10)
    #[cfg(feature = "protocol-773")]
    V773,

    /// Protocol version 765 (Minecraft 1.20.3/1.20.4)
    #[cfg(feature = "protocol-765")]
    V765,
}

impl ProtocolVersion {
    /// Attempt to create a `ProtocolVersion` from a raw protocol version number.
    ///
    /// Returns `None` if the version is not supported or not enabled via features.
    #[must_use]
    pub const fn from_raw(version: i32) -> Option<Self> {
        match version {
            #[cfg(feature = "protocol-773")]
            773 => Some(Self::V773),

            #[cfg(feature = "protocol-765")]
            765 => Some(Self::V765),

            _ => None,
        }
    }

    /// Get the raw protocol version number.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        match self {
            #[cfg(feature = "protocol-773")]
            Self::V773 => 773,

            #[cfg(feature = "protocol-765")]
            Self::V765 => 765,
        }
    }

    /// Gets a list of human-readable version names (e.g., `["1.21.10", "1.21.9"]`).
    #[must_use]
    pub const fn names(self) -> &'static [&'static str] {
        match self {
            #[cfg(feature = "protocol-773")]
            Self::V773 => &["1.21.10", "1.21.9"],

            #[cfg(feature = "protocol-765")]
            Self::V765 => &["1.20.4", "1.20.3"],
        }
    }

    /// Gets the primary version name (e.g., "1.21.10").
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.names()[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "protocol-773")]
    fn test_v773() {
        let version = ProtocolVersion::from_raw(773).unwrap();
        assert_eq!(version, ProtocolVersion::V773);
        assert_eq!(version.as_raw(), 773);
        assert_eq!(version.names(), &["1.21.10", "1.21.9"]);
        assert_eq!(version.name(), "1.21.10");
    }

    #[test]
    #[cfg(feature = "protocol-765")]
    fn test_v765() {
        let version = ProtocolVersion::from_raw(765).unwrap();
        assert_eq!(version, ProtocolVersion::V765);
        assert_eq!(version.as_raw(), 765);
        assert_eq!(version.names(), &["1.20.4", "1.20.3"]);
        assert_eq!(version.name(), "1.20.4");
    }

    #[test]
    fn test_unknown_version() {
        assert!(ProtocolVersion::from_raw(999).is_none());
    }
}
