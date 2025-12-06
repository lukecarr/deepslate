//! Minecraft proxy logic for handling connections.

// Connection handlers hold authentication state, resulting in large futures.
// This is expected and acceptable for this use case.
#![allow(clippy::large_futures)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::io::{Read, Write};

use bytes::BytesMut;
use deepslate_mc::ProtocolVersion;
use deepslate_mc::codec::{RawPacket, read_packet, write_packet};
use deepslate_mc::packets::{
    EncryptionRequest, EncryptionResponse, Handshake, LoginDisconnect, LoginPluginRequest,
    LoginPluginResponse, LoginStart, NextState, Ping, Pong, SetCompression, StatusRequest,
    StatusResponse,
};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::auth::{AuthKeys, Cfb8Cipher, PlayerProfile, verify_session};
use crate::server::ServerPool;
use crate::velocity::{VELOCITY_CHANNEL, build_forwarding_data};

/// Minecraft proxy that handles connections.
pub struct Proxy {
    /// Pool of upstream servers
    pool: Arc<ServerPool>,
    /// Session counter for logging
    session_counter: AtomicUsize,
    /// Maximum players to show in status
    max_players: u32,
    /// Server MOTD (Message of the Day)
    motd: String,
    /// Velocity forwarding secret (required for upstream communication)
    velocity_secret: Option<Vec<u8>>,
}

impl Proxy {
    /// Create a new proxy with the given server pool.
    #[must_use]
    pub fn new(pool: Arc<ServerPool>) -> Self {
        Self {
            pool,
            session_counter: AtomicUsize::new(0),
            max_players: 100,
            motd: "A Deepslate Proxy Server".to_string(),
            velocity_secret: None,
        }
    }

    /// Set the maximum players shown in server status.
    #[must_use]
    pub const fn with_max_players(mut self, max_players: u32) -> Self {
        self.max_players = max_players;
        self
    }

    /// Set the server MOTD.
    #[must_use]
    pub fn with_motd(mut self, motd: impl Into<String>) -> Self {
        self.motd = motd.into();
        self
    }

    /// Set the Velocity forwarding secret.
    ///
    /// This is required for online-mode authentication with Velocity forwarding.
    #[must_use]
    pub fn with_velocity_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.velocity_secret = Some(secret.into());
        self
    }

    /// Run the proxy, accepting connections on the given listener.
    pub async fn run(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((client, client_addr)) => {
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        proxy.handle_connection(client, client_addr).await;
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {e}");
                }
            }
        }
    }

    /// Handle a single client connection.
    async fn handle_connection(&self, mut client: TcpStream, client_addr: SocketAddr) {
        let session_id = self.session_counter.fetch_add(1, Ordering::SeqCst);

        async {
            // Read the handshake packet
            let handshake = match self.read_handshake(&mut client).await {
                Ok(h) => h,
                Err(e) => {
                    debug!("Failed to read handshake: {e}");
                    return;
                }
            };

            debug!(
                protocol = handshake.protocol_version,
                address = %handshake.server_address,
                port = handshake.server_port,
                next_state = ?handshake.next_state,
                "Received handshake"
            );

            // Determine the protocol version (use client's version or fallback)
            let version = ProtocolVersion::from_raw(handshake.protocol_version);

            match handshake.next_state {
                NextState::Status => {
                    if let Err(e) = self.handle_status(&mut client, version).await {
                        debug!("Status handler error: {e}");
                    }
                }
                NextState::Login | NextState::Transfer => {
                    self.handle_login(&mut client, &handshake, version, client_addr)
                        .await;
                }
            }
        }
        .instrument(info_span!(
            "conn",
            sid = session_id,
            ip = %client_addr.ip(),
            port = client_addr.port()
        ))
        .await;
    }

    /// Read and parse the handshake packet.
    async fn read_handshake(
        &self,
        client: &mut TcpStream,
    ) -> Result<Handshake, deepslate_mc::ProtocolError> {
        let raw = read_packet(client).await?;
        Handshake::from_raw(&raw)
    }

    /// Handle a status (server list ping) request.
    async fn handle_status(
        &self,
        client: &mut TcpStream,
        version: Option<ProtocolVersion>,
    ) -> Result<(), deepslate_mc::ProtocolError> {
        // Read StatusRequest (should be empty, packet ID 0x00)
        let raw = read_packet(client).await?;
        let _request = StatusRequest::from_raw(&raw)?;

        debug!("Received status request");

        // Use the client's protocol version if supported, otherwise use default
        #[cfg(feature = "mc-1_21_10")]
        let default_version = ProtocolVersion::V773;
        #[cfg(all(not(feature = "mc-1_21_10"), feature = "mc-1_20_4"))]
        let default_version = ProtocolVersion::V765;

        let active_version = version.unwrap_or(default_version);
        // Use the primary version name for the status response
        let (version_name, protocol_version) = (active_version.name(), active_version.as_raw());

        // Build status response JSON
        let status_json = json!({
            "version": {
                "name": version_name,
                "protocol": protocol_version
            },
            "players": {
                "max": self.max_players,
                "online": 0,
                "sample": []
            },
            "description": {
                "text": self.motd
            },
            "enforcesSecureChat": false
        });

        // Send StatusResponse
        let response = StatusResponse::new(status_json.to_string());
        write_packet(client, &response.to_raw()).await?;

        debug!("Sent status response");

        // Read Ping and send Pong with same payload
        let raw = read_packet(client).await?;
        let client_ping = Ping::from_raw(&raw)?;

        debug!(payload = client_ping.payload, "Received ping");

        let response = Pong::new(client_ping.payload);
        write_packet(client, &response.to_raw()).await?;

        debug!("Sent pong");

        Ok(())
    }

    /// Handle a login request with online-mode authentication and Velocity forwarding.
    async fn handle_login(
        &self,
        client: &mut TcpStream,
        handshake: &Handshake,
        version: Option<ProtocolVersion>,
        client_addr: SocketAddr,
    ) {
        // Log if client is using an unsupported protocol version
        if version.is_none() {
            warn!(
                protocol = handshake.protocol_version,
                "Client using unsupported protocol version"
            );
        }

        // Check if Velocity secret is configured
        let Some(velocity_secret) = &self.velocity_secret else {
            warn!("Velocity secret not configured, cannot authenticate");
            let _ = self
                .send_disconnect(
                    client,
                    None,
                    "Server misconfigured: missing velocity secret",
                )
                .await;
            return;
        };

        // Step 1: Read LoginStart from client
        let login_start = match self.read_login_start(client).await {
            Ok(ls) => ls,
            Err(e) => {
                debug!("Failed to read LoginStart: {e}");
                return;
            }
        };

        info!(username = %login_start.name, "Player connecting");

        // Step 2: Authenticate with Mojang (encryption handshake)
        let (profile, shared_secret) = match self
            .authenticate_client(client, &login_start.name, client_addr.ip())
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!(username = %login_start.name, "Authentication failed: {e}");
                let _ = self
                    .send_disconnect(client, None, &format!("Authentication failed: {e}"))
                    .await;
                return;
            }
        };

        info!(
            username = %profile.username,
            uuid = %profile.uuid,
            "Player authenticated"
        );

        // Enable encryption for client communication
        // Note: We don't send LoginSuccess here - we'll forward the upstream's LoginSuccess
        // which may contain additional properties (like player textures)
        let mut client_encryptor = Cfb8Cipher::new(&shared_secret, &shared_secret);
        let mut client_decryptor = Cfb8Cipher::new(&shared_secret, &shared_secret);

        // Step 3: Select and connect to upstream server
        let Some(server) = self.pool.select() else {
            warn!("No available upstream servers");
            return;
        };

        let mut upstream = match TcpStream::connect(&server.addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    upstream = %server.addr,
                    server_id = %server.id,
                    "Failed to connect: {e}"
                );
                return;
            }
        };

        info!(
            upstream = %server.addr,
            server_id = %server.id,
            "Connected to upstream"
        );

        // Step 4: Send handshake to upstream
        if let Err(e) = write_packet(&mut upstream, &handshake.to_raw()).await {
            error!("Failed to send handshake to upstream: {e}");
            return;
        }

        // Step 5: Send LoginStart to upstream
        let upstream_login = LoginStart::new(&profile.username, profile.uuid);
        if let Err(e) = write_packet(&mut upstream, &upstream_login.to_raw()).await {
            error!("Failed to send LoginStart to upstream: {e}");
            return;
        }

        // Step 6: Handle Velocity forwarding handshake with upstream
        // This will forward SetCompression and LoginSuccess to the client
        if let Err(e) = self
            .handle_velocity_forwarding(
                &mut upstream,
                client,
                &mut client_encryptor,
                velocity_secret,
                client_addr,
                &profile,
            )
            .await
        {
            error!("Velocity forwarding failed: {e}");
            return;
        }

        // Step 7: Forward all remaining traffic bidirectionally with encryption
        if let Err(e) = forward_encrypted(
            client,
            &mut upstream,
            &mut client_encryptor,
            &mut client_decryptor,
        )
        .await
        {
            debug!("Connection closed: {e}");
        } else {
            info!(username = %profile.username, "Session ended");
        }
    }

    /// Read and parse `LoginStart` packet from client.
    async fn read_login_start(
        &self,
        client: &mut TcpStream,
    ) -> Result<LoginStart, deepslate_mc::ProtocolError> {
        let raw = read_packet(client).await?;
        LoginStart::from_raw(&raw)
    }

    /// Authenticate client using online-mode encryption.
    ///
    /// Returns the player profile and the shared secret for encryption.
    async fn authenticate_client(
        &self,
        client: &mut TcpStream,
        username: &str,
        client_ip: std::net::IpAddr,
    ) -> Result<(PlayerProfile, [u8; 16]), Box<dyn std::error::Error + Send + Sync>> {
        // Generate RSA keypair for this session
        let auth_keys = AuthKeys::generate()?;

        // Send EncryptionRequest
        let encryption_request =
            EncryptionRequest::new(auth_keys.public_key_der(), auth_keys.verify_token());
        write_packet(client, &encryption_request.to_raw()).await?;

        debug!("Sent EncryptionRequest");

        // Read EncryptionResponse
        let raw = read_packet(client).await?;
        let encryption_response = EncryptionResponse::from_raw(&raw)?;

        debug!("Received EncryptionResponse");

        // Decrypt shared secret and verify token
        let shared_secret = auth_keys.decrypt_response(
            &encryption_response.shared_secret,
            &encryption_response.verify_token,
        )?;

        debug!("Decrypted shared secret");

        // Calculate server hash for Mojang verification
        let server_hash = auth_keys.calculate_server_hash(&shared_secret);

        // Verify session with Mojang
        let profile = verify_session(username, &server_hash, Some(&client_ip.to_string())).await?;

        debug!(uuid = %profile.uuid, "Session verified with Mojang");

        Ok((profile, shared_secret))
    }

    /// Handle Velocity modern forwarding handshake with upstream.
    async fn handle_velocity_forwarding(
        &self,
        upstream: &mut TcpStream,
        client: &mut TcpStream,
        client_encryptor: &mut Cfb8Cipher,
        secret: &[u8],
        client_addr: SocketAddr,
        profile: &PlayerProfile,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut compression_threshold: Option<i32> = None;

        loop {
            // Read packet, handling compression if enabled
            let raw = if let Some(threshold) = compression_threshold {
                read_packet_compressed(upstream, threshold).await?
            } else {
                read_packet(upstream).await?
            };

            match raw.id {
                // LoginPluginRequest
                0x04 => {
                    let request = LoginPluginRequest::from_raw(&raw)?;

                    if request.channel == VELOCITY_CHANNEL {
                        debug!("Received Velocity hello request");

                        // Build and send Velocity forwarding response
                        let forwarding_data = build_forwarding_data(
                            secret,
                            client_addr.ip(),
                            profile.uuid,
                            &profile.username,
                            &profile.properties,
                        );

                        let response =
                            LoginPluginResponse::success(request.message_id, forwarding_data);
                        write_packet(upstream, &response.to_raw()).await?;

                        debug!("Sent Velocity forwarding response");
                    } else {
                        // Unknown plugin request, send failure
                        let response = LoginPluginResponse::failure(request.message_id);
                        write_packet(upstream, &response.to_raw()).await?;
                    }
                }

                // LoginSuccess (0x02) - forward to client (encrypted, maybe compressed) and we're done
                0x02 => {
                    debug!("Upstream sent LoginSuccess");
                    if let Some(threshold) = compression_threshold {
                        write_packet_encrypted_compressed(
                            client,
                            &raw,
                            client_encryptor,
                            threshold,
                        )
                        .await?;
                    } else {
                        write_packet_encrypted(client, &raw, client_encryptor).await?;
                    }
                    break;
                }

                // SetCompression (0x03) - forward to client FIRST (uncompressed), then enable compression
                0x03 => {
                    let set_compression = SetCompression::from_raw(&raw)?;
                    debug!(
                        threshold = set_compression.threshold,
                        "Upstream sent SetCompression"
                    );
                    // Send SetCompression in uncompressed format (compression not yet enabled for client)
                    write_packet_encrypted(client, &raw, client_encryptor).await?;
                    // NOW enable compression for subsequent packets
                    compression_threshold = Some(set_compression.threshold);
                }

                // LoginDisconnect (0x00) - forward (encrypted, maybe compressed) and return error
                0x00 => {
                    // Try to parse the disconnect reason for logging
                    let reason = LoginDisconnect::from_raw(&raw)
                        .map_or_else(|_| "unknown".to_string(), |d| d.reason);
                    warn!(reason = %reason, "Upstream sent LoginDisconnect");
                    if let Some(threshold) = compression_threshold {
                        write_packet_encrypted_compressed(
                            client,
                            &raw,
                            client_encryptor,
                            threshold,
                        )
                        .await?;
                    } else {
                        write_packet_encrypted(client, &raw, client_encryptor).await?;
                    }
                    return Err(format!("Upstream rejected login: {reason}").into());
                }

                id => {
                    warn!(
                        packet_id = id,
                        "Unexpected packet during Velocity handshake"
                    );
                }
            }
        }

        Ok(())
    }

    /// Send a disconnect message to the client.
    async fn send_disconnect(
        &self,
        client: &mut TcpStream,
        encryptor: Option<&mut Cfb8Cipher>,
        reason: &str,
    ) -> Result<(), deepslate_mc::ProtocolError> {
        let disconnect = LoginDisconnect::from_json(json!({"text": reason}).to_string());
        if let Some(enc) = encryptor {
            write_packet_encrypted(client, &disconnect.to_raw(), enc).await
        } else {
            write_packet(client, &disconnect.to_raw()).await
        }
    }
}

// =============================================================================
// Compressed packet I/O helpers
// =============================================================================

/// Read a packet with compression support.
///
/// After `SetCompression`, packets have format: `[length][data_length][data]`
/// - If `data_length` == 0: data is uncompressed (`packet_id` + payload)
/// - If `data_length` > 0: data is zlib compressed
async fn read_packet_compressed(
    reader: &mut TcpStream,
    _threshold: i32,
) -> Result<RawPacket, deepslate_mc::ProtocolError> {
    // Read packet length
    let packet_length = read_varint_async(reader).await?;
    let packet_length =
        usize::try_from(packet_length).map_err(|_| deepslate_mc::ProtocolError::PacketTooLong {
            len: 0,
            max: deepslate_mc::codec::MAX_PACKET_SIZE,
        })?;

    // Read the packet data
    let mut data = vec![0u8; packet_length];
    reader.read_exact(&mut data).await?;

    // Parse data_length (uncompressed size, 0 = not compressed)
    let (data_length, data_length_size) = read_varint_from_slice(&data)?;

    let packet_data = if data_length == 0 {
        // Not compressed - rest of data is packet_id + payload
        data[data_length_size..].to_vec()
    } else {
        // Compressed - decompress using zlib
        let compressed = &data[data_length_size..];
        #[allow(clippy::cast_sign_loss)]
        let mut decompressed = Vec::with_capacity(data_length as usize);
        let mut decoder = ZlibDecoder::new(compressed);
        decoder.read_to_end(&mut decompressed)?;
        decompressed
    };

    // Parse packet ID from the (possibly decompressed) data
    let (id, id_len) = read_varint_from_slice(&packet_data)?;
    let payload = BytesMut::from(&packet_data[id_len..]);

    Ok(RawPacket::new(id, payload))
}

/// Read a varint asynchronously.
async fn read_varint_async(reader: &mut TcpStream) -> Result<i32, deepslate_mc::ProtocolError> {
    let mut value: i32 = 0;
    let mut position: u32 = 0;

    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;

        value |= i32::from(byte[0] & 0x7F) << position;

        if byte[0] & 0x80 == 0 {
            break;
        }

        position += 7;
        if position >= 32 {
            return Err(deepslate_mc::ProtocolError::VarIntTooLong);
        }
    }

    Ok(value)
}

// =============================================================================
// Encrypted packet I/O helpers
// =============================================================================

/// Write a packet with encryption (uncompressed format).
async fn write_packet_encrypted(
    writer: &mut TcpStream,
    packet: &RawPacket,
    cipher: &mut Cfb8Cipher,
) -> Result<(), deepslate_mc::ProtocolError> {
    use deepslate_mc::varint::varint_len;

    // Calculate total length (packet_id + payload)
    let id_len = varint_len(packet.id);
    let total_len = id_len + packet.payload.len();

    // Build the packet: [length][id][payload]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let total_len_i32 = total_len as i32;

    let mut buf = Vec::with_capacity(varint_len(total_len_i32) + total_len);
    write_varint_to_vec(&mut buf, total_len_i32);
    write_varint_to_vec(&mut buf, packet.id);
    buf.extend_from_slice(&packet.payload);

    // Encrypt the entire buffer
    cipher.encrypt(&mut buf);

    writer.write_all(&buf).await?;
    Ok(())
}

/// Write a packet with encryption and compression.
///
/// Format: `[packet_length][data_length][compressed_data]`
/// where `data_length` is the uncompressed size (or 0 if not compressed).
async fn write_packet_encrypted_compressed(
    writer: &mut TcpStream,
    packet: &RawPacket,
    cipher: &mut Cfb8Cipher,
    threshold: i32,
) -> Result<(), deepslate_mc::ProtocolError> {
    use deepslate_mc::varint::varint_len;

    // Build uncompressed packet data: [packet_id][payload]
    let id_len = varint_len(packet.id);
    let uncompressed_len = id_len + packet.payload.len();

    let mut uncompressed = Vec::with_capacity(uncompressed_len);
    write_varint_to_vec(&mut uncompressed, packet.id);
    uncompressed.extend_from_slice(&packet.payload);

    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    let threshold_usize = threshold as usize;

    let mut buf = Vec::new();

    if uncompressed_len >= threshold_usize {
        // Compress the data
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&uncompressed)?;
        let compressed = encoder.finish()?;

        // data_length = uncompressed size
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let data_length = uncompressed_len as i32;
        let data_length_len = varint_len(data_length);

        // packet_length = data_length varint + compressed data
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let packet_length = (data_length_len + compressed.len()) as i32;

        write_varint_to_vec(&mut buf, packet_length);
        write_varint_to_vec(&mut buf, data_length);
        buf.extend_from_slice(&compressed);
    } else {
        // Don't compress - data_length = 0
        // packet_length = 1 (data_length varint) + uncompressed data
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let packet_length = (1 + uncompressed_len) as i32;

        write_varint_to_vec(&mut buf, packet_length);
        write_varint_to_vec(&mut buf, 0); // data_length = 0 means not compressed
        buf.extend_from_slice(&uncompressed);
    }

    // Encrypt the entire buffer
    cipher.encrypt(&mut buf);

    writer.write_all(&buf).await?;
    Ok(())
}

/// Forward traffic bidirectionally with encryption on the client side.
async fn forward_encrypted(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    client_encryptor: &mut Cfb8Cipher,
    client_decryptor: &mut Cfb8Cipher,
) -> Result<(), std::io::Error> {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // Decrypt from client
            client_decryptor.decrypt(&mut buf[..n]);
            // Send to upstream (unencrypted)
            upstream_write.write_all(&buf[..n]).await?;
        }
        upstream_write.shutdown().await
    };

    let upstream_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = upstream_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // Encrypt for client
            client_encryptor.encrypt(&mut buf[..n]);
            // Send to client (encrypted)
            client_write.write_all(&buf[..n]).await?;
        }
        client_write.shutdown().await
    };

    tokio::select! {
        result = client_to_upstream => result,
        result = upstream_to_client => result,
    }
}

/// Write a varint to a Vec.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn write_varint_to_vec(buf: &mut Vec<u8>, mut value: i32) {
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (value & 0x7F) as u8;
        value = ((value as u32) >> 7) as i32;

        if value != 0 {
            byte |= 0x80;
        }

        buf.push(byte);

        if value == 0 {
            break;
        }
    }
}

/// Read a varint from a slice, returning the value and number of bytes consumed.
fn read_varint_from_slice(data: &[u8]) -> Result<(i32, usize), deepslate_mc::ProtocolError> {
    let mut value: i32 = 0;
    let mut position: u32 = 0;
    let mut bytes_read = 0;

    for &byte in data {
        bytes_read += 1;
        value |= i32::from(byte & 0x7F) << position;

        if byte & 0x80 == 0 {
            return Ok((value, bytes_read));
        }

        position += 7;
        if position >= 32 {
            return Err(deepslate_mc::ProtocolError::VarIntTooLong);
        }
    }

    Err(deepslate_mc::ProtocolError::VarIntTooLong)
}
