//! Online-mode authentication for Minecraft.
//!
//! This module handles the full online-mode authentication flow:
//! 1. Generate RSA keypair for encryption handshake
//! 2. Exchange shared secret with client
//! 3. Verify session with Mojang's sessionserver API
//! 4. Enable AES-128-CFB8 encryption

use std::io;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use bytes::Bytes;
use num_bigint::BigInt;
use rand::Rng;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use deepslate_mc::packets::Property;

/// RSA key size in bits.
const RSA_KEY_SIZE: usize = 1024;

/// Verify token size in bytes.
const VERIFY_TOKEN_SIZE: usize = 4;

/// Mojang session server URL.
const SESSION_SERVER_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined";

/// Error type for authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("PKCS8 error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::spki::Error),

    #[error("Verify token mismatch")]
    VerifyTokenMismatch,

    #[error("Session verification failed: {0}")]
    SessionVerification(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Authentication keypair for online-mode.
pub struct AuthKeys {
    /// RSA private key for decryption.
    private_key: RsaPrivateKey,
    /// RSA public key for encryption (DER-encoded).
    public_key_der: Bytes,
    /// Random verify token.
    verify_token: [u8; VERIFY_TOKEN_SIZE],
}

impl AuthKeys {
    /// Generate a new authentication keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if RSA key generation fails.
    pub fn generate() -> Result<Self, AuthError> {
        // Generate RSA keypair
        let private_key = RsaPrivateKey::new(&mut rand::rng(), RSA_KEY_SIZE)?;
        let public_key = RsaPublicKey::from(&private_key);

        // Encode public key as DER
        let public_key_der = public_key.to_public_key_der()?.into_vec();

        // Generate random verify token
        let mut verify_token = [0u8; VERIFY_TOKEN_SIZE];
        rand::rng().fill(&mut verify_token);

        Ok(Self {
            private_key,
            public_key_der: Bytes::from(public_key_der),
            verify_token,
        })
    }

    /// Get the DER-encoded public key.
    #[must_use]
    pub fn public_key_der(&self) -> Bytes {
        self.public_key_der.clone()
    }

    /// Get the verify token.
    #[must_use]
    pub fn verify_token(&self) -> Bytes {
        Bytes::copy_from_slice(&self.verify_token)
    }

    /// Decrypt the shared secret and verify token from the client.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails or verify token doesn't match.
    pub fn decrypt_response(
        &self,
        encrypted_secret: &[u8],
        encrypted_token: &[u8],
    ) -> Result<[u8; 16], AuthError> {
        // Decrypt shared secret
        let shared_secret = self
            .private_key
            .decrypt(Pkcs1v15Encrypt, encrypted_secret)?;

        // Decrypt and verify token
        let decrypted_token = self.private_key.decrypt(Pkcs1v15Encrypt, encrypted_token)?;

        if decrypted_token != self.verify_token {
            return Err(AuthError::VerifyTokenMismatch);
        }

        // Shared secret should be exactly 16 bytes
        let mut secret = [0u8; 16];
        secret.copy_from_slice(&shared_secret[..16]);

        Ok(secret)
    }

    /// Calculate the server hash for Mojang session verification.
    ///
    /// The hash is calculated as: `SHA1(server_id + shared_secret + public_key)`
    /// and formatted as a signed hex string (Minecraft's non-standard format).
    #[must_use]
    pub fn calculate_server_hash(&self, shared_secret: &[u8; 16]) -> String {
        let mut hasher = Sha1::new();

        // Server ID is empty string for online-mode
        hasher.update(b"");
        hasher.update(shared_secret);
        hasher.update(&self.public_key_der);

        let hash = hasher.finalize();

        // Convert to Minecraft's signed hex format
        minecraft_hex_digest(&hash)
    }
}

/// Player profile returned from Mojang session verification.
#[derive(Debug, Clone)]
pub struct PlayerProfile {
    /// Player UUID.
    pub uuid: Uuid,
    /// Player username.
    pub username: String,
    /// Player properties (e.g., skin textures).
    pub properties: Vec<Property>,
}

/// Response from Mojang session server.
#[derive(Debug, Deserialize)]
struct SessionResponse {
    id: String,
    name: String,
    #[serde(default)]
    properties: Vec<SessionProperty>,
}

#[derive(Debug, Deserialize)]
struct SessionProperty {
    name: String,
    value: String,
    signature: Option<String>,
}

/// Verify a player's session with Mojang's session server.
///
/// # Errors
///
/// Returns an error if verification fails or the session is invalid.
pub async fn verify_session(
    username: &str,
    server_hash: &str,
    client_ip: Option<&str>,
) -> Result<PlayerProfile, AuthError> {
    let client = reqwest::Client::new();

    let mut url = format!("{SESSION_SERVER_URL}?username={username}&serverId={server_hash}");

    // Optionally include client IP for additional verification
    if let Some(ip) = client_ip {
        use std::fmt::Write;
        let _ = write!(url, "&ip={ip}");
    }

    let response = client.get(&url).send().await?;

    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Err(AuthError::SessionVerification(
            "Session not found (player may not have authenticated with Mojang)".to_string(),
        ));
    }

    if !response.status().is_success() {
        return Err(AuthError::SessionVerification(format!(
            "Session server returned status {}",
            response.status()
        )));
    }

    let session: SessionResponse = response.json().await?;

    // Parse UUID (Mojang returns it without hyphens)
    let uuid = Uuid::parse_str(&session.id).map_err(|e| {
        AuthError::SessionVerification(format!("Invalid UUID from session server: {e}"))
    })?;

    // Convert properties
    let properties = session
        .properties
        .into_iter()
        .map(|p| Property {
            name: p.name,
            value: p.value,
            signature: p.signature,
        })
        .collect();

    Ok(PlayerProfile {
        uuid,
        username: session.name,
        properties,
    })
}

/// AES-128-CFB8 cipher state.
///
/// CFB8 mode encrypts/decrypts one byte at a time, using the previous
/// ciphertext byte to update the IV for the next byte.
pub struct Cfb8Cipher {
    cipher: Aes128,
    iv: [u8; 16],
}

impl Cfb8Cipher {
    /// Create a new CFB8 cipher with the given key and IV.
    ///
    /// For Minecraft, both key and IV are the shared secret.
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        Self { cipher, iv: *iv }
    }

    /// Encrypt data in place using CFB8 mode.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            // Encrypt the IV to get the keystream byte
            let mut block = GenericArray::clone_from_slice(&self.iv);
            self.cipher.encrypt_block(&mut block);

            // XOR the plaintext byte with the first byte of the encrypted block
            let ciphertext_byte = *byte ^ block[0];
            *byte = ciphertext_byte;

            // Shift the IV left by 1 byte and append the ciphertext byte
            self.iv.copy_within(1.., 0);
            self.iv[15] = ciphertext_byte;
        }
    }

    /// Decrypt data in place using CFB8 mode.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            // Encrypt the IV to get the keystream byte
            let mut block = GenericArray::clone_from_slice(&self.iv);
            self.cipher.encrypt_block(&mut block);

            // Save the ciphertext byte before decryption
            let ciphertext_byte = *byte;

            // XOR the ciphertext byte with the first byte of the encrypted block
            *byte ^= block[0];

            // Shift the IV left by 1 byte and append the ciphertext byte
            self.iv.copy_within(1.., 0);
            self.iv[15] = ciphertext_byte;
        }
    }
}

/// Convert a SHA1 hash to Minecraft's signed hex digest format.
///
/// Minecraft uses a non-standard format where the hash is treated as a
/// two's complement signed number and converted to hex without leading zeros.
fn minecraft_hex_digest(hash: &[u8]) -> String {
    let bigint = BigInt::from_signed_bytes_be(hash);
    format!("{bigint:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_keys_generation() {
        let keys = AuthKeys::generate().unwrap();

        // Public key should be DER-encoded
        assert!(!keys.public_key_der.is_empty());

        // Verify token should be 4 bytes
        assert_eq!(keys.verify_token().len(), VERIFY_TOKEN_SIZE);
    }

    #[test]
    fn test_minecraft_hex_digest() {
        // Test vectors from wiki.vg
        // "Notch" should produce: 4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48
        let hash1: [u8; 20] = [
            0x4e, 0xd1, 0xf4, 0x6b, 0xbe, 0x04, 0xbc, 0x75, 0x6b, 0xcb, 0x17, 0xc0, 0xc7, 0xce,
            0x3e, 0x46, 0x32, 0xf0, 0x6a, 0x48,
        ];
        assert_eq!(
            minecraft_hex_digest(&hash1),
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
        );

        // "jeb_" should produce: -7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1
        let hash2: [u8; 20] = [
            0x83, 0x62, 0xa4, 0xff, 0xbb, 0x3e, 0xcf, 0xef, 0x65, 0xa2, 0x84, 0xa0, 0x4a, 0x3c,
            0xe8, 0x3f, 0xd4, 0xb1, 0xd7, 0x3f,
        ];
        assert_eq!(
            minecraft_hex_digest(&hash2),
            "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1"
        );
    }

    #[test]
    fn test_cfb8_cipher_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];

        let mut encryptor = Cfb8Cipher::new(&key, &iv);
        let mut decryptor = Cfb8Cipher::new(&key, &iv);

        let original = b"Hello, Minecraft!".to_vec();
        let mut data = original.clone();

        encryptor.encrypt(&mut data);
        assert_ne!(data, original); // Should be encrypted

        decryptor.decrypt(&mut data);
        assert_eq!(data, original); // Should be decrypted back
    }
}
