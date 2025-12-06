//! Protocol error types.

use std::io;

use thiserror::Error;

/// Errors that can occur when reading or writing Minecraft protocol data.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A `VarInt` was too long (more than 5 bytes).
    #[error("VarInt too long")]
    VarIntTooLong,

    /// A `VarLong` was too long (more than 10 bytes).
    #[error("VarLong too long")]
    VarLongTooLong,

    /// A string exceeded the maximum length.
    #[error("String too long: {len} bytes (max {max})")]
    StringTooLong {
        /// The actual length of the string.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// A packet exceeded the maximum length.
    #[error("Packet too long: {len} bytes (max {max})")]
    PacketTooLong {
        /// The actual length of the packet.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// An invalid packet ID was received.
    #[error("Invalid packet ID: {0}")]
    InvalidPacketId(i32),

    /// An invalid next state was received in a handshake.
    #[error("Invalid next state: {0}")]
    InvalidNextState(i32),

    /// An unsupported protocol version was received.
    #[error("Unsupported protocol version: {0}")]
    UnsupportedProtocol(i32),
}

/// Result type alias using [`ProtocolError`].
pub type Result<T> = std::result::Result<T, ProtocolError>;
