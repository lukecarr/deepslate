//! Minecraft protocol packets.
//!
//! Packets are organized by connection state:
//! - Handshake: Initial connection state
//! - Status: Server list ping
//! - Login: Authentication (not yet implemented)
//! - Play: In-game (not yet implemented)

pub mod handshake;
pub mod status;

pub use handshake::{Handshake, NextState};
pub use status::{Ping, Pong, StatusRequest, StatusResponse};
