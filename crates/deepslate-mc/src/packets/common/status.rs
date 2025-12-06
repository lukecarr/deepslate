//! Status protocol packets.
//!
//! The status protocol is used by clients to query server information
//! without joining. This packet format is stable across all supported
//! protocol versions.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::BytesMut;

use crate::codec::{RawPacket, read_string, write_string};
use crate::error::{ProtocolError, Result};
use crate::packets::traits::{ConnectionState, Packet};

/// Maximum JSON response length (32 KiB).
const MAX_JSON_LENGTH: usize = 32 * 1024;

/// Status Request packet (client -> server).
///
/// This is an empty packet that requests server status.
#[derive(Debug, Clone, Default)]
pub struct StatusRequest;

impl Packet for StatusRequest {
    const ID: i32 = 0x00;
    const STATE: ConnectionState = ConnectionState::Status;
}

impl StatusRequest {
    /// Parse a status request from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet ID is invalid.
    pub const fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }
        Ok(Self)
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        RawPacket::empty(Self::ID)
    }
}

/// Status Response packet (server -> client).
///
/// Contains a JSON object with server information.
#[derive(Debug, Clone)]
pub struct StatusResponse {
    /// JSON response containing server status.
    pub json: String,
}

impl Packet for StatusResponse {
    const ID: i32 = 0x00;
    const STATE: ConnectionState = ConnectionState::Status;
}

impl StatusResponse {
    /// Create a new status response with the given JSON.
    #[must_use]
    pub fn new(json: impl Into<String>) -> Self {
        Self { json: json.into() }
    }

    /// Parse a status response from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let json = read_string(&mut buf, MAX_JSON_LENGTH)?;

        Ok(Self { json })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_string(&mut payload, &self.json);
        RawPacket::new(Self::ID, payload)
    }
}

/// Ping packet (client -> server).
///
/// Client sends a timestamp, server echoes it back.
#[derive(Debug, Clone)]
pub struct Ping {
    /// Arbitrary payload (usually a timestamp).
    pub payload: i64,
}

impl Packet for Ping {
    const ID: i32 = 0x01;
    const STATE: ConnectionState = ConnectionState::Status;
}

impl Ping {
    /// Create a new ping with the given payload.
    #[must_use]
    pub const fn new(payload: i64) -> Self {
        Self { payload }
    }

    /// Parse a ping from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut cursor = std::io::Cursor::new(&packet.payload[..]);
        let payload = cursor.read_i64::<BigEndian>()?;

        Ok(Self { payload })
    }

    /// Encode to a raw packet.
    ///
    /// # Panics
    ///
    /// This function will not panic - the unwrap is infallible when writing to a `Vec`.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::with_capacity(8);
        let mut cursor = std::io::Cursor::new(Vec::with_capacity(8));
        // Writing to a Vec<u8> cursor never fails
        cursor.write_i64::<BigEndian>(self.payload).unwrap();
        payload.extend_from_slice(cursor.get_ref());
        RawPacket::new(Self::ID, payload)
    }
}

/// Pong packet (server -> client).
///
/// Server echoes back the ping payload.
#[derive(Debug, Clone)]
pub struct Pong {
    /// The payload from the ping packet.
    pub payload: i64,
}

impl Packet for Pong {
    const ID: i32 = 0x01;
    const STATE: ConnectionState = ConnectionState::Status;
}

impl Pong {
    /// Create a new pong with the given payload.
    #[must_use]
    pub const fn new(payload: i64) -> Self {
        Self { payload }
    }

    /// Parse a pong from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut cursor = std::io::Cursor::new(&packet.payload[..]);
        let payload = cursor.read_i64::<BigEndian>()?;

        Ok(Self { payload })
    }

    /// Encode to a raw packet.
    ///
    /// # Panics
    ///
    /// This function will not panic - the unwrap is infallible when writing to a `Vec`.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::with_capacity(8);
        let mut cursor = std::io::Cursor::new(Vec::with_capacity(8));
        // Writing to a Vec<u8> cursor never fails
        cursor.write_i64::<BigEndian>(self.payload).unwrap();
        payload.extend_from_slice(cursor.get_ref());
        RawPacket::new(Self::ID, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_request_roundtrip() {
        let original = StatusRequest;
        let raw = original.to_raw();
        let parsed = StatusRequest::from_raw(&raw).unwrap();
        assert_eq!(raw.id, StatusRequest::ID);
        // StatusRequest has no fields to compare
        let _ = parsed;
    }

    #[test]
    fn test_status_response_roundtrip() {
        let json =
            r#"{"version":{"name":"1.21.10","protocol":773},"players":{"max":100,"online":0}}"#;
        let original = StatusResponse::new(json);
        let raw = original.to_raw();
        let parsed = StatusResponse::from_raw(&raw).unwrap();
        assert_eq!(parsed.json, json);
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn test_ping_pong_roundtrip() {
        let ping_packet = Ping::new(1_234_567_890);
        let raw = ping_packet.to_raw();
        let parsed = Ping::from_raw(&raw).unwrap();
        assert_eq!(parsed.payload, ping_packet.payload);

        let pong_packet = Pong::new(parsed.payload);
        let raw = pong_packet.to_raw();
        let parsed = Pong::from_raw(&raw).unwrap();
        assert_eq!(parsed.payload, pong_packet.payload);
    }

    #[test]
    fn test_negative_ping_payload() {
        let ping = Ping::new(-9_876_543_210);
        let raw = ping.to_raw();
        let parsed = Ping::from_raw(&raw).unwrap();
        assert_eq!(parsed.payload, ping.payload);
    }
}
