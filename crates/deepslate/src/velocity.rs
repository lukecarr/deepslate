//! Velocity modern forwarding implementation.
//!
//! This module handles the Velocity modern forwarding protocol, which allows
//! the proxy to securely forward authenticated player information to backend
//! servers using HMAC-SHA256 signatures.

use std::net::IpAddr;

use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use deepslate_mc::packets::Property;

type HmacSha256 = Hmac<Sha256>;

/// The current Velocity forwarding protocol version.
pub const VELOCITY_FORWARDING_VERSION: i32 = 1;

/// The Velocity forwarding channel identifier.
pub const VELOCITY_CHANNEL: &str = "velocity:player_info";

/// Build Velocity modern forwarding data.
///
/// This creates the signed payload that the proxy sends to the backend server
/// to identify the authenticated player.
///
/// # Arguments
///
/// * `secret` - The shared HMAC secret between proxy and backend
/// * `client_addr` - The IP address of the connecting client
/// * `uuid` - The player's authenticated UUID
/// * `username` - The player's username
/// * `properties` - Player properties (e.g., skin textures from Mojang)
///
/// # Returns
///
/// A `Bytes` containing the HMAC signature followed by the forwarding data.
#[must_use]
pub fn build_forwarding_data(
    secret: &[u8],
    client_addr: IpAddr,
    uuid: Uuid,
    username: &str,
    properties: &[Property],
) -> Bytes {
    // Build the forwarding data (without signature)
    let mut data = BytesMut::new();

    // Protocol version
    write_varint(&mut data, VELOCITY_FORWARDING_VERSION);

    // Client address as string
    write_string(&mut data, &client_addr.to_string());

    // Player UUID (16 bytes, big-endian)
    data.put_slice(uuid.as_bytes());

    // Player username
    write_string(&mut data, username);

    // Properties
    write_properties(&mut data, properties);

    // Calculate HMAC-SHA256 signature
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&data);
    let signature = mac.finalize().into_bytes();

    // Build final payload: signature + data
    let mut result = BytesMut::with_capacity(32 + data.len());
    result.put_slice(&signature);
    result.extend_from_slice(&data);

    result.freeze()
}

// =============================================================================
// Helper functions
// =============================================================================

/// Write a `VarInt` to a buffer.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn write_varint(buf: &mut BytesMut, mut value: i32) {
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (value & 0x7F) as u8;
        value = ((value as u32) >> 7) as i32;

        if value != 0 {
            byte |= 0x80;
        }

        buf.put_u8(byte);

        if value == 0 {
            break;
        }
    }
}

/// Write a Minecraft string to a buffer.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn write_string(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    write_varint(buf, bytes.len() as i32);
    buf.put_slice(bytes);
}

/// Write player properties to a buffer.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn write_properties(buf: &mut BytesMut, properties: &[Property]) {
    write_varint(buf, properties.len() as i32);

    for prop in properties {
        write_string(buf, &prop.name);
        write_string(buf, &prop.value);

        if let Some(sig) = &prop.signature {
            buf.put_u8(1);
            write_string(buf, sig);
        } else {
            buf.put_u8(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_forwarding_data() {
        let secret = b"test_secret";
        let client_addr: IpAddr = "192.168.1.100".parse().unwrap();
        let uuid = Uuid::new_v4();
        let username = "TestPlayer";
        let properties = vec![];

        let data = build_forwarding_data(secret, client_addr, uuid, username, &properties);

        // Should have at least 32 bytes for signature
        assert!(data.len() >= 32);

        // First 32 bytes are the HMAC signature
        let signature = &data[..32];
        let payload = &data[32..];

        // Verify signature
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload);
        assert!(mac.verify_slice(signature).is_ok());
    }

    #[test]
    fn test_build_forwarding_data_with_properties() {
        let secret = b"test_secret";
        let client_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let uuid = Uuid::new_v4();
        let username = "SkinPlayer";
        let properties = vec![Property {
            name: "textures".to_string(),
            value: "base64encodeddata".to_string(),
            signature: Some("signaturedata".to_string()),
        }];

        let data = build_forwarding_data(secret, client_addr, uuid, username, &properties);

        // Verify signature is valid
        let signature = &data[..32];
        let payload = &data[32..];

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload);
        assert!(mac.verify_slice(signature).is_ok());
    }
}
