//! Minecraft protocol implementation for Deepslate.
//!
//! This crate provides types and utilities for reading and writing
//! Minecraft protocol packets.

pub mod codec;
pub mod error;
pub mod packets;
pub mod varint;

pub use error::ProtocolError;
