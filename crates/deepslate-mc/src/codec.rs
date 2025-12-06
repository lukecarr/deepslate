//! Packet framing codec for Minecraft protocol.
//!
//! Minecraft packets are framed as:
//! - `[VarInt length][VarInt packet_id][payload...]`
//!
//! The length includes the packet ID and payload, but not itself.

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ProtocolError, Result};
use crate::varint::{read_varint, varint_len, write_varint_sync};

/// Maximum packet size (2 MiB, same as vanilla).
pub const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024;

/// A raw packet with its ID and payload.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// The packet ID.
    pub id: i32,
    /// The packet payload (without the packet ID).
    pub payload: BytesMut,
}

impl RawPacket {
    /// Create a new raw packet with the given ID and payload.
    #[must_use]
    pub const fn new(id: i32, payload: BytesMut) -> Self {
        Self { id, payload }
    }

    /// Create a new raw packet with the given ID and an empty payload.
    #[must_use]
    pub fn empty(id: i32) -> Self {
        Self {
            id,
            payload: BytesMut::new(),
        }
    }
}

/// Read a raw packet from an async reader.
///
/// # Errors
///
/// Returns an error if:
/// - An I/O error occurs
/// - The packet length exceeds [`MAX_PACKET_SIZE`]
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RawPacket> {
    // Read packet length
    let length = read_varint(reader).await?;

    // Validate length is non-negative and within bounds
    let length = usize::try_from(length).map_err(|_| ProtocolError::PacketTooLong {
        len: 0,
        max: MAX_PACKET_SIZE,
    })?;

    if length > MAX_PACKET_SIZE {
        return Err(ProtocolError::PacketTooLong {
            len: length,
            max: MAX_PACKET_SIZE,
        });
    }

    // Read the entire packet data (packet_id + payload)
    let mut data = vec![0u8; length];
    reader.read_exact(&mut data).await?;

    // Parse packet ID from the data
    let mut cursor = std::io::Cursor::new(&data);
    let id = read_varint_sync(&mut cursor)?;

    #[allow(clippy::cast_possible_truncation)]
    let id_len = cursor.position() as usize;

    // The rest is the payload
    let payload = BytesMut::from(&data[id_len..]);

    Ok(RawPacket { id, payload })
}

/// Write a raw packet to an async writer.
///
/// # Errors
///
/// Returns an error if an I/O error occurs.
pub async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &RawPacket) -> Result<()> {
    // Calculate total length (packet_id + payload)
    let id_len = varint_len(packet.id);
    let total_len = id_len + packet.payload.len();

    // Build the packet: [length][id][payload]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let total_len_i32 = total_len as i32;

    let mut buf = Vec::with_capacity(varint_len(total_len_i32) + total_len);
    write_varint_sync(&mut buf, total_len_i32);
    write_varint_sync(&mut buf, packet.id);
    buf.extend_from_slice(&packet.payload);

    writer.write_all(&buf).await?;

    Ok(())
}

/// Read a `VarInt` synchronously from a cursor.
fn read_varint_sync<R: std::io::Read>(reader: &mut R) -> Result<i32> {
    let mut value: i32 = 0;
    let mut position: u32 = 0;
    let mut byte = [0u8; 1];

    loop {
        std::io::Read::read_exact(reader, &mut byte)?;
        value |= i32::from(byte[0] & 0x7F) << position;

        if byte[0] & 0x80 == 0 {
            break;
        }

        position += 7;
        if position >= 32 {
            return Err(ProtocolError::VarIntTooLong);
        }
    }

    Ok(value)
}

/// Read a Minecraft string from a buffer.
///
/// Minecraft strings are: `[VarInt length][UTF-8 bytes]`
///
/// # Errors
///
/// Returns an error if the string exceeds the maximum length.
pub fn read_string(buf: &mut impl Buf, max_len: usize) -> Result<String> {
    let len = read_varint_from_buf(buf)?;

    // Validate length is non-negative
    let len = usize::try_from(len).map_err(|_| ProtocolError::StringTooLong {
        len: 0,
        max: max_len * 4,
    })?;

    if len > max_len * 4 {
        // Max 4 bytes per char in UTF-8
        return Err(ProtocolError::StringTooLong {
            len,
            max: max_len * 4,
        });
    }

    let mut bytes = vec![0u8; len];
    buf.copy_to_slice(&mut bytes);

    // Note: We don't validate the char count here for simplicity
    String::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()).into())
}

/// Write a Minecraft string to a buffer.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn write_string(buf: &mut impl BufMut, s: &str) {
    let bytes = s.as_bytes();
    write_varint_to_buf(buf, bytes.len() as i32);
    buf.put_slice(bytes);
}

/// Read a `VarInt` from a buffer.
///
/// # Errors
///
/// Returns an error if the `VarInt` is malformed (too long).
pub fn read_varint_from_buf(buf: &mut impl Buf) -> Result<i32> {
    let mut value: i32 = 0;
    let mut position: u32 = 0;

    loop {
        let byte = buf.get_u8();
        value |= i32::from(byte & 0x7F) << position;

        if byte & 0x80 == 0 {
            break;
        }

        position += 7;
        if position >= 32 {
            return Err(ProtocolError::VarIntTooLong);
        }
    }

    Ok(value)
}

/// Write a `VarInt` to a buffer.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub fn write_varint_to_buf(buf: &mut impl BufMut, mut value: i32) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_write_packet() {
        let original = RawPacket {
            id: 0x00,
            payload: BytesMut::from(&b"hello"[..]),
        };

        // Write packet to buffer
        let mut buf = Vec::new();
        write_packet(&mut buf, &original).await.unwrap();

        // Read it back
        let mut cursor = Cursor::new(buf);
        let read = read_packet(&mut cursor).await.unwrap();

        assert_eq!(read.id, original.id);
        assert_eq!(read.payload, original.payload);
    }

    #[tokio::test]
    async fn test_empty_packet() {
        let original = RawPacket::empty(0x01);

        let mut buf = Vec::new();
        write_packet(&mut buf, &original).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let read = read_packet(&mut cursor).await.unwrap();

        assert_eq!(read.id, 0x01);
        assert!(read.payload.is_empty());
    }

    #[test]
    fn test_read_write_string() {
        let original = "Hello, Minecraft!";

        let mut buf = BytesMut::new();
        write_string(&mut buf, original);

        let read = read_string(&mut buf.freeze(), 256).unwrap();
        assert_eq!(read, original);
    }

    #[test]
    fn test_string_too_long() {
        let mut buf = BytesMut::new();
        // Write a string that claims to be very long
        write_varint_to_buf(&mut buf, 10000);

        let result = read_string(&mut buf.freeze(), 16);
        assert!(matches!(result, Err(ProtocolError::StringTooLong { .. })));
    }
}
