//! Handshake packet definitions.
//!
//! The handshake is the first packet sent by the client and determines
//! whether this is a status ping or a login attempt.

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};

use crate::codec::{
    RawPacket, read_string, read_varint_from_buf, write_string, write_varint_to_buf,
};
use crate::error::{ProtocolError, Result};

/// Handshake packet ID.
pub const PACKET_ID: i32 = 0x00;

/// Maximum server address length.
const MAX_SERVER_ADDRESS: usize = 255;

/// The next state after handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextState {
    /// Status request (server list ping).
    Status = 1,
    /// Login request.
    Login = 2,
    /// Transfer (1.20.5+).
    Transfer = 3,
}

impl TryFrom<i32> for NextState {
    type Error = ProtocolError;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            1 => Ok(Self::Status),
            2 => Ok(Self::Login),
            3 => Ok(Self::Transfer),
            _ => Err(ProtocolError::InvalidNextState(value)),
        }
    }
}

/// Handshake packet sent by the client.
///
/// This is always the first packet in a connection.
#[derive(Debug, Clone)]
pub struct Handshake {
    /// The protocol version the client is using.
    pub protocol_version: i32,
    /// The server address the client connected to.
    pub server_address: String,
    /// The server port the client connected to.
    pub server_port: u16,
    /// The next state: Status (1) or Login (2).
    pub next_state: NextState,
}

impl Handshake {
    /// Parse a handshake from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != PACKET_ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();

        let protocol_version = read_varint_from_buf(&mut buf)?;
        let server_address = read_string(&mut buf, MAX_SERVER_ADDRESS)?;
        let server_port = std::io::Cursor::new(buf.as_ref()).read_u16::<BigEndian>()?;
        buf.advance(2);
        let next_state = NextState::try_from(read_varint_from_buf(&mut buf)?)?;

        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }

    /// Encode the handshake to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();

        write_varint_to_buf(&mut payload, self.protocol_version);
        write_string(&mut payload, &self.server_address);
        payload.put_u16(self.server_port);
        write_varint_to_buf(&mut payload, self.next_state as i32);

        RawPacket::new(PACKET_ID, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let original = Handshake {
            protocol_version: 773,
            server_address: "localhost".to_string(),
            server_port: 25565,
            next_state: NextState::Status,
        };

        let raw = original.to_raw();
        let parsed = Handshake::from_raw(&raw).unwrap();

        assert_eq!(parsed.protocol_version, original.protocol_version);
        assert_eq!(parsed.server_address, original.server_address);
        assert_eq!(parsed.server_port, original.server_port);
        assert_eq!(parsed.next_state, original.next_state);
    }

    #[test]
    fn test_next_state_conversion() {
        assert_eq!(NextState::try_from(1).unwrap(), NextState::Status);
        assert_eq!(NextState::try_from(2).unwrap(), NextState::Login);
        assert_eq!(NextState::try_from(3).unwrap(), NextState::Transfer);
        assert!(NextState::try_from(0).is_err());
        assert!(NextState::try_from(4).is_err());
    }
}
