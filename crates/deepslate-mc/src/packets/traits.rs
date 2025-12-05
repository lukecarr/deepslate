//! Packet traits for serialization and deserialization.
//!
//! These traits provide a common interface for reading and writing
//! Minecraft protocol packets across different protocol versions.

use bytes::{Buf, BufMut};

use crate::error::Result;
use crate::version::ProtocolVersion;

/// The connection state for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Handshaking state (initial connection).
    Handshaking,
    /// Status state (server list ping).
    Status,
    /// Login state (authentication).
    Login,
    /// Play state (in-game).
    Play,
}

/// A Minecraft protocol packet.
///
/// This trait provides metadata about a packet type, including its ID
/// and the connection state it belongs to.
pub trait Packet: Sized {
    /// The packet ID.
    const ID: i32;

    /// The connection state this packet belongs to.
    const STATE: ConnectionState;
}

/// A packet that can be read from a buffer.
///
/// Implementations should handle version-specific differences in packet format.
pub trait Readable: Sized {
    /// Read the packet from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read from
    /// * `version` - The protocol version to use for parsing
    ///
    /// # Errors
    ///
    /// Returns an error if the packet data is malformed.
    fn read(buf: &mut impl Buf, version: ProtocolVersion) -> Result<Self>;
}

/// A packet that can be written to a buffer.
///
/// Implementations should handle version-specific differences in packet format.
pub trait Writable {
    /// Write the packet to a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to write to
    /// * `version` - The protocol version to use for serialization
    fn write(&self, buf: &mut impl BufMut, version: ProtocolVersion);
}
