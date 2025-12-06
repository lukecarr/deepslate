//! Login protocol packets.
//!
//! The login protocol handles player authentication. In online mode, this includes
//! encryption negotiation and Mojang session verification. This packet format is
//! stable across all supported protocol versions.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use uuid::Uuid;

use crate::codec::{
    RawPacket, read_string, read_varint_from_buf, write_string, write_varint_to_buf,
};
use crate::error::{ProtocolError, Result};
use crate::packets::traits::{ConnectionState, Packet};

/// Maximum username length (16 characters).
const MAX_USERNAME_LENGTH: usize = 16;

/// Maximum channel identifier length.
const MAX_CHANNEL_LENGTH: usize = 256;

/// Maximum public key length (512 bytes for RSA-1024).
const MAX_PUBLIC_KEY_LENGTH: usize = 512;

/// Maximum verify token length (typically 4 bytes).
const MAX_VERIFY_TOKEN_LENGTH: usize = 256;

/// Maximum disconnect reason length.
const MAX_DISCONNECT_REASON_LENGTH: usize = 262_144;

// =============================================================================
// LoginStart (Client -> Server, ID: 0x00)
// =============================================================================

/// Login Start packet (client -> server).
///
/// Sent by the client to begin the login process.
#[derive(Debug, Clone)]
pub struct LoginStart {
    /// The player's username.
    pub name: String,
    /// The player's UUID (sent by client in 1.19.1+).
    pub uuid: Uuid,
}

impl Packet for LoginStart {
    const ID: i32 = 0x00;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl LoginStart {
    /// Create a new login start packet.
    #[must_use]
    pub fn new(name: impl Into<String>, uuid: Uuid) -> Self {
        Self {
            name: name.into(),
            uuid,
        }
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let name = read_string(&mut buf, MAX_USERNAME_LENGTH)?;
        let uuid = read_uuid(&mut buf);

        Ok(Self { name, uuid })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_string(&mut payload, &self.name);
        write_uuid(&mut payload, self.uuid);
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// EncryptionRequest (Server -> Client, ID: 0x01)
// =============================================================================

/// Encryption Request packet (server -> client).
///
/// Sent by the server to initiate encryption.
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    /// Server ID (empty string for online-mode servers).
    pub server_id: String,
    /// The server's public key (DER-encoded).
    pub public_key: Bytes,
    /// Random verify token.
    pub verify_token: Bytes,
    /// Whether the client should authenticate with Mojang (1.20.5+).
    pub should_authenticate: bool,
}

impl Packet for EncryptionRequest {
    const ID: i32 = 0x01;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl EncryptionRequest {
    /// Create a new encryption request.
    #[must_use]
    pub const fn new(public_key: Bytes, verify_token: Bytes) -> Self {
        Self {
            server_id: String::new(),
            public_key,
            verify_token,
            should_authenticate: true,
        }
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let server_id = read_string(&mut buf, 20)?;
        let public_key = read_byte_array(&mut buf, MAX_PUBLIC_KEY_LENGTH)?;
        let verify_token = read_byte_array(&mut buf, MAX_VERIFY_TOKEN_LENGTH)?;
        let should_authenticate = if buf.has_remaining() {
            buf.get_u8() != 0
        } else {
            true
        };

        Ok(Self {
            server_id,
            public_key,
            verify_token,
            should_authenticate,
        })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_string(&mut payload, &self.server_id);
        write_byte_array(&mut payload, &self.public_key);
        write_byte_array(&mut payload, &self.verify_token);
        payload.put_u8(u8::from(self.should_authenticate));
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// EncryptionResponse (Client -> Server, ID: 0x01)
// =============================================================================

/// Encryption Response packet (client -> server).
///
/// Sent by the client in response to an encryption request.
#[derive(Debug, Clone)]
pub struct EncryptionResponse {
    /// The shared secret, encrypted with the server's public key.
    pub shared_secret: Bytes,
    /// The verify token, encrypted with the server's public key.
    pub verify_token: Bytes,
}

impl Packet for EncryptionResponse {
    const ID: i32 = 0x01;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl EncryptionResponse {
    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let shared_secret = read_byte_array(&mut buf, 256)?;
        let verify_token = read_byte_array(&mut buf, 256)?;

        Ok(Self {
            shared_secret,
            verify_token,
        })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_byte_array(&mut payload, &self.shared_secret);
        write_byte_array(&mut payload, &self.verify_token);
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// LoginSuccess (Server -> Client, ID: 0x02)
// =============================================================================

/// A player property (e.g., textures).
#[derive(Debug, Clone)]
pub struct Property {
    /// Property name.
    pub name: String,
    /// Property value.
    pub value: String,
    /// Optional signature.
    pub signature: Option<String>,
}

/// Login Success packet (server -> client).
///
/// Sent when login is complete. Client should transition to Play state.
#[derive(Debug, Clone)]
pub struct LoginSuccess {
    /// The player's UUID.
    pub uuid: Uuid,
    /// The player's username.
    pub username: String,
    /// Player properties (e.g., skin textures).
    pub properties: Vec<Property>,
}

impl Packet for LoginSuccess {
    const ID: i32 = 0x02;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl LoginSuccess {
    /// Create a new login success packet.
    #[must_use]
    pub fn new(uuid: Uuid, username: impl Into<String>) -> Self {
        Self {
            uuid,
            username: username.into(),
            properties: Vec::new(),
        }
    }

    /// Add a property to the login success.
    #[must_use]
    pub fn with_property(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        signature: Option<String>,
    ) -> Self {
        self.properties.push(Property {
            name: name.into(),
            value: value.into(),
            signature,
        });
        self
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let uuid = read_uuid(&mut buf);
        let username = read_string(&mut buf, MAX_USERNAME_LENGTH)?;

        let property_count = read_varint_from_buf(&mut buf)?;
        #[allow(clippy::cast_sign_loss)]
        let mut properties = Vec::with_capacity(property_count as usize);

        for _ in 0..property_count {
            let name = read_string(&mut buf, 32767)?;
            let value = read_string(&mut buf, 32767)?;
            let has_signature = buf.get_u8() != 0;
            let signature = if has_signature {
                Some(read_string(&mut buf, 32767)?)
            } else {
                None
            };
            properties.push(Property {
                name,
                value,
                signature,
            });
        }

        Ok(Self {
            uuid,
            username,
            properties,
        })
    }

    /// Encode to a raw packet.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_uuid(&mut payload, self.uuid);
        write_string(&mut payload, &self.username);

        write_varint_to_buf(&mut payload, self.properties.len() as i32);
        for prop in &self.properties {
            write_string(&mut payload, &prop.name);
            write_string(&mut payload, &prop.value);
            if let Some(sig) = &prop.signature {
                payload.put_u8(1);
                write_string(&mut payload, sig);
            } else {
                payload.put_u8(0);
            }
        }

        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// SetCompression (Server -> Client, ID: 0x03)
// =============================================================================

/// Set Compression packet (server -> client).
///
/// Enables packet compression for the connection.
#[derive(Debug, Clone)]
pub struct SetCompression {
    /// Compression threshold. Packets larger than this will be compressed.
    /// A value of -1 disables compression.
    pub threshold: i32,
}

impl Packet for SetCompression {
    const ID: i32 = 0x03;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl SetCompression {
    /// Create a new set compression packet.
    #[must_use]
    pub const fn new(threshold: i32) -> Self {
        Self { threshold }
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let threshold = read_varint_from_buf(&mut buf)?;

        Ok(Self { threshold })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_varint_to_buf(&mut payload, self.threshold);
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// LoginPluginRequest (Server -> Client, ID: 0x04)
// =============================================================================

/// Login Plugin Request packet (server -> client).
///
/// Used for custom login flows like Velocity forwarding.
#[derive(Debug, Clone)]
pub struct LoginPluginRequest {
    /// Message ID for correlating request/response.
    pub message_id: i32,
    /// Channel identifier (e.g., "velocity:hello").
    pub channel: String,
    /// Plugin data.
    pub data: Bytes,
}

impl Packet for LoginPluginRequest {
    const ID: i32 = 0x04;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl LoginPluginRequest {
    /// Create a new login plugin request.
    #[must_use]
    pub fn new(message_id: i32, channel: impl Into<String>, data: Bytes) -> Self {
        Self {
            message_id,
            channel: channel.into(),
            data,
        }
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let message_id = read_varint_from_buf(&mut buf)?;
        let channel = read_string(&mut buf, MAX_CHANNEL_LENGTH)?;
        // Remaining bytes are the data
        let data = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            message_id,
            channel,
            data,
        })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_varint_to_buf(&mut payload, self.message_id);
        write_string(&mut payload, &self.channel);
        payload.extend_from_slice(&self.data);
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// LoginPluginResponse (Client -> Server, ID: 0x02)
// =============================================================================

/// Login Plugin Response packet (client -> server).
///
/// Response to a login plugin request.
#[derive(Debug, Clone)]
pub struct LoginPluginResponse {
    /// Message ID from the request.
    pub message_id: i32,
    /// Whether the client understood the request.
    pub successful: bool,
    /// Response data (only present if successful).
    pub data: Option<Bytes>,
}

impl Packet for LoginPluginResponse {
    const ID: i32 = 0x02;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl LoginPluginResponse {
    /// Create a successful response with data.
    #[must_use]
    pub const fn success(message_id: i32, data: Bytes) -> Self {
        Self {
            message_id,
            successful: true,
            data: Some(data),
        }
    }

    /// Create an unsuccessful response.
    #[must_use]
    pub const fn failure(message_id: i32) -> Self {
        Self {
            message_id,
            successful: false,
            data: None,
        }
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let message_id = read_varint_from_buf(&mut buf)?;
        let successful = buf.get_u8() != 0;
        let data = if successful && buf.has_remaining() {
            Some(buf.copy_to_bytes(buf.remaining()))
        } else {
            None
        };

        Ok(Self {
            message_id,
            successful,
            data,
        })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_varint_to_buf(&mut payload, self.message_id);
        payload.put_u8(u8::from(self.successful));
        if let Some(data) = &self.data {
            payload.extend_from_slice(data);
        }
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// LoginDisconnect (Server -> Client, ID: 0x00)
// =============================================================================

/// Login Disconnect packet (server -> client).
///
/// Sent when the server disconnects the client during login.
#[derive(Debug, Clone)]
pub struct LoginDisconnect {
    /// The disconnect reason (JSON chat component).
    pub reason: String,
}

impl Packet for LoginDisconnect {
    const ID: i32 = 0x00;
    const STATE: ConnectionState = ConnectionState::Login;
}

impl LoginDisconnect {
    /// Create a new disconnect packet with a plain text reason.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Create a disconnect packet with a JSON chat component.
    #[must_use]
    pub fn from_json(json: impl Into<String>) -> Self {
        Self {
            reason: json.into(),
        }
    }

    /// Parse from a raw packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn from_raw(packet: &RawPacket) -> Result<Self> {
        if packet.id != Self::ID {
            return Err(ProtocolError::InvalidPacketId(packet.id));
        }

        let mut buf = packet.payload.clone().freeze();
        let reason = read_string(&mut buf, MAX_DISCONNECT_REASON_LENGTH)?;

        Ok(Self { reason })
    }

    /// Encode to a raw packet.
    #[must_use]
    pub fn to_raw(&self) -> RawPacket {
        let mut payload = BytesMut::new();
        write_string(&mut payload, &self.reason);
        RawPacket::new(Self::ID, payload)
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Read a UUID from a buffer.
fn read_uuid(buf: &mut impl Buf) -> Uuid {
    let mut bytes = [0u8; 16];
    buf.copy_to_slice(&mut bytes);
    Uuid::from_bytes(bytes)
}

/// Write a UUID to a buffer.
fn write_uuid(buf: &mut impl BufMut, uuid: Uuid) {
    buf.put_slice(uuid.as_bytes());
}

/// Read a length-prefixed byte array.
fn read_byte_array(buf: &mut impl Buf, max_len: usize) -> Result<Bytes> {
    let len = read_varint_from_buf(buf)?;
    let len = usize::try_from(len).map_err(|_| ProtocolError::StringTooLong {
        len: 0,
        max: max_len,
    })?;

    if len > max_len {
        return Err(ProtocolError::StringTooLong { len, max: max_len });
    }

    Ok(buf.copy_to_bytes(len))
}

/// Write a length-prefixed byte array.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn write_byte_array(buf: &mut impl BufMut, data: &[u8]) {
    write_varint_to_buf(buf, data.len() as i32);
    buf.put_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_start_roundtrip() {
        let uuid = Uuid::new_v4();
        let original = LoginStart::new("TestPlayer", uuid);
        let raw = original.to_raw();
        let parsed = LoginStart::from_raw(&raw).unwrap();

        assert_eq!(parsed.name, "TestPlayer");
        assert_eq!(parsed.uuid, uuid);
    }

    #[test]
    fn test_encryption_request_roundtrip() {
        let original = EncryptionRequest::new(
            Bytes::from_static(b"fake_public_key"),
            Bytes::from_static(b"token"),
        );
        let raw = original.to_raw();
        let parsed = EncryptionRequest::from_raw(&raw).unwrap();

        assert_eq!(parsed.server_id, "");
        assert_eq!(parsed.public_key, original.public_key);
        assert_eq!(parsed.verify_token, original.verify_token);
        assert!(parsed.should_authenticate);
    }

    #[test]
    fn test_login_success_roundtrip() {
        let uuid = Uuid::new_v4();
        let original = LoginSuccess::new(uuid, "TestPlayer").with_property(
            "textures",
            "base64data",
            Some("signature".to_string()),
        );
        let raw = original.to_raw();
        let parsed = LoginSuccess::from_raw(&raw).unwrap();

        assert_eq!(parsed.uuid, uuid);
        assert_eq!(parsed.username, "TestPlayer");
        assert_eq!(parsed.properties.len(), 1);
        assert_eq!(parsed.properties[0].name, "textures");
        assert_eq!(
            parsed.properties[0].signature,
            Some("signature".to_string())
        );
    }

    #[test]
    fn test_set_compression_roundtrip() {
        let original = SetCompression::new(256);
        let raw = original.to_raw();
        let parsed = SetCompression::from_raw(&raw).unwrap();

        assert_eq!(parsed.threshold, 256);
    }

    #[test]
    fn test_login_plugin_request_roundtrip() {
        let original = LoginPluginRequest::new(1, "velocity:hello", Bytes::from_static(b"\x01"));
        let raw = original.to_raw();
        let parsed = LoginPluginRequest::from_raw(&raw).unwrap();

        assert_eq!(parsed.message_id, 1);
        assert_eq!(parsed.channel, "velocity:hello");
        assert_eq!(parsed.data, Bytes::from_static(b"\x01"));
    }

    #[test]
    fn test_login_plugin_response_roundtrip() {
        let original = LoginPluginResponse::success(1, Bytes::from_static(b"response_data"));
        let raw = original.to_raw();
        let parsed = LoginPluginResponse::from_raw(&raw).unwrap();

        assert_eq!(parsed.message_id, 1);
        assert!(parsed.successful);
        assert_eq!(parsed.data, Some(Bytes::from_static(b"response_data")));
    }

    #[test]
    fn test_login_disconnect_roundtrip() {
        let original = LoginDisconnect::new(r#"{"text":"You are banned!"}"#);
        let raw = original.to_raw();
        let parsed = LoginDisconnect::from_raw(&raw).unwrap();

        assert_eq!(parsed.reason, r#"{"text":"You are banned!"}"#);
    }
}
