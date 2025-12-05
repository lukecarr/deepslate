//! Minecraft protocol packets.
//!
//! Packets are organized by:
//! - `common`: Packets stable across all protocol versions
//! - `v773`: Protocol 773 (Minecraft 1.21.9/1.21.10)
//! - `v765`: Protocol 765 (Minecraft 1.20.3/1.20.4)
//!
//! Connection states:
//! - Handshake: Initial connection state
//! - Status: Server list ping
//! - Login: Authentication (not yet implemented)
//! - Play: In-game (not yet implemented)

pub mod common;
pub mod traits;

#[cfg(feature = "protocol-773")]
pub mod v773;

#[cfg(feature = "protocol-765")]
pub mod v765;

// Re-export common packets
pub use common::{Handshake, NextState};

// Re-export traits
pub use traits::{ConnectionState, Packet, Readable, Writable};

// Re-export version-specific status packets based on enabled features
// Default to v773 for backwards compatibility
#[cfg(feature = "protocol-773")]
pub use v773::{Ping, Pong, StatusRequest, StatusResponse};
