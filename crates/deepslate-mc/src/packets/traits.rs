//! Packet traits for serialization and deserialization.
//!
//! These traits provide a common interface for Minecraft protocol packets.

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
