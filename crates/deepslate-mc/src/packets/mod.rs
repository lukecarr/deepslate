//! Minecraft protocol packets.
//!
//! Packets are organized by:
//! - `common`: Packets stable across all protocol versions
//!
//! Connection states:
//! - Handshake: Initial connection state
//! - Status: Server list ping
//! - Login: Authentication
//! - Play: In-game (not yet implemented)

pub mod common;
pub mod traits;

// Re-export common packets
pub use common::{
    EncryptionRequest, EncryptionResponse, Handshake, LoginDisconnect, LoginPluginRequest,
    LoginPluginResponse, LoginStart, LoginSuccess, NextState, Ping, Pong, Property, SetCompression,
    StatusRequest, StatusResponse,
};

// Re-export traits
pub use traits::{ConnectionState, Packet};
