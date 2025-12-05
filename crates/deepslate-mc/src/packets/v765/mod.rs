//! Protocol version 765 packets (Minecraft 1.20.3/1.20.4).
//!
//! This module contains version-specific packet implementations for
//! protocol version 765.

pub mod status;

pub use status::{Ping, Pong, StatusRequest, StatusResponse};
