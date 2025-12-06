//! `VarInt` and `VarLong` encoding/decoding for Minecraft protocol.
//!
//! Minecraft uses a variable-length integer encoding where each byte
//! uses 7 bits for data and 1 bit to indicate if more bytes follow.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ProtocolError, Result};

/// Segment bits mask (lower 7 bits).
const SEGMENT_BITS: u8 = 0x7F;

/// Continue bit (high bit).
const CONTINUE_BIT: u8 = 0x80;

/// Read a `VarInt` from an async reader.
///
/// # Errors
///
/// Returns an error if:
/// - An I/O error occurs
/// - The `VarInt` is longer than 5 bytes
pub async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> Result<i32> {
    let mut value: i32 = 0;
    let mut position: u32 = 0;

    loop {
        let byte = reader.read_u8().await?;
        value |= i32::from(byte & SEGMENT_BITS) << position;

        if byte & CONTINUE_BIT == 0 {
            break;
        }

        position += 7;
        if position >= 32 {
            return Err(ProtocolError::VarIntTooLong);
        }
    }

    Ok(value)
}

/// Write a `VarInt` to an async writer.
///
/// # Errors
///
/// Returns an error if an I/O error occurs.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub async fn write_varint<W: AsyncWrite + Unpin>(writer: &mut W, mut value: i32) -> Result<usize> {
    let mut bytes_written = 0;

    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (value & i32::from(SEGMENT_BITS)) as u8;
        value = ((value as u32) >> 7) as i32;

        if value != 0 {
            byte |= CONTINUE_BIT;
        }

        writer.write_u8(byte).await?;
        bytes_written += 1;

        if value == 0 {
            break;
        }
    }

    Ok(bytes_written)
}

/// Write a `VarInt` to a byte buffer synchronously.
///
/// Returns the number of bytes written.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub fn write_varint_sync(buf: &mut Vec<u8>, mut value: i32) -> usize {
    let mut bytes_written = 0;

    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (value & i32::from(SEGMENT_BITS)) as u8;
        value = ((value as u32) >> 7) as i32;

        if value != 0 {
            byte |= CONTINUE_BIT;
        }

        buf.push(byte);
        bytes_written += 1;

        if value == 0 {
            break;
        }
    }

    bytes_written
}

/// Calculate the number of bytes needed to encode a `VarInt`.
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub const fn varint_len(value: i32) -> usize {
    // Convert to unsigned for bit manipulation
    let value = value as u32;

    if value == 0 {
        return 1;
    }

    // Calculate the number of 7-bit segments needed
    let bits_needed = 32 - value.leading_zeros();
    (bits_needed as usize).div_ceil(7)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    async fn roundtrip(value: i32) {
        let mut buf = Vec::new();
        write_varint(&mut buf, value).await.unwrap();
        assert_eq!(buf.len(), varint_len(value));

        let mut cursor = Cursor::new(buf);
        let read_value = read_varint(&mut cursor).await.unwrap();
        assert_eq!(read_value, value);
    }

    #[tokio::test]
    async fn test_varint_zero() {
        roundtrip(0).await;
    }

    #[tokio::test]
    async fn test_varint_positive() {
        roundtrip(1).await;
        roundtrip(127).await;
        roundtrip(128).await;
        roundtrip(255).await;
        roundtrip(25565).await;
        roundtrip(2_097_151).await;
        roundtrip(i32::MAX).await;
    }

    #[tokio::test]
    async fn test_varint_negative() {
        roundtrip(-1).await;
        roundtrip(-127).await;
        roundtrip(i32::MIN).await;
    }

    #[test]
    fn test_varint_len() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(1), 1);
        assert_eq!(varint_len(127), 1);
        assert_eq!(varint_len(128), 2);
        assert_eq!(varint_len(16383), 2);
        assert_eq!(varint_len(16384), 3);
        assert_eq!(varint_len(2_097_151), 3);
        assert_eq!(varint_len(2_097_152), 4);
        assert_eq!(varint_len(268_435_455), 4);
        assert_eq!(varint_len(268_435_456), 5);
        assert_eq!(varint_len(i32::MAX), 5);
        // Negative numbers always use 5 bytes
        assert_eq!(varint_len(-1), 5);
        assert_eq!(varint_len(i32::MIN), 5);
    }

    #[tokio::test]
    async fn test_known_values() {
        // Test vectors from wiki.vg
        let test_cases = [
            (0, vec![0x00]),
            (1, vec![0x01]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (255, vec![0xff, 0x01]),
            (25565, vec![0xdd, 0xc7, 0x01]),
            (2_097_151, vec![0xff, 0xff, 0x7f]),
            (2_147_483_647, vec![0xff, 0xff, 0xff, 0xff, 0x07]),
            (-1, vec![0xff, 0xff, 0xff, 0xff, 0x0f]),
            (-2_147_483_648, vec![0x80, 0x80, 0x80, 0x80, 0x08]),
        ];

        for (value, expected_bytes) in test_cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).await.unwrap();
            assert_eq!(buf, expected_bytes, "write failed for {value}");

            let mut cursor = Cursor::new(expected_bytes);
            let read_value = read_varint(&mut cursor).await.unwrap();
            assert_eq!(read_value, value, "read failed for {value}");
        }
    }

    #[tokio::test]
    async fn test_varint_too_long() {
        // 6 bytes with continue bits set - should fail
        let bytes = vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut cursor = Cursor::new(bytes);
        let result = read_varint(&mut cursor).await;
        assert!(matches!(result, Err(ProtocolError::VarIntTooLong)));
    }

    #[test]
    fn test_write_varint_sync() {
        let mut buf = Vec::new();
        let len = write_varint_sync(&mut buf, 25565);
        assert_eq!(len, 3);
        assert_eq!(buf, vec![0xdd, 0xc7, 0x01]);
    }
}
