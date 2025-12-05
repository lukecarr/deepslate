//! Protocol version 773 packets (Minecraft 1.21.9/1.21.10).
//!
//! This module contains version-specific packet implementations for
//! protocol version 773.

pub mod status;

pub use status::{Ping, Pong, StatusRequest, StatusResponse};
