//! Minecraft proxy logic for handling connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use deepslate_mc::ProtocolVersion;
use deepslate_mc::codec::{read_packet, write_packet};
use deepslate_mc::packets::{Handshake, NextState, Ping, Pong, StatusRequest, StatusResponse};
use serde_json::json;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::server::ServerPool;

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
                    self.handle_login(&mut client, &handshake, version).await;
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

    /// Handle a login request by forwarding to an upstream server.
    async fn handle_login(
        &self,
        client: &mut TcpStream,
        handshake: &Handshake,
        version: Option<ProtocolVersion>,
    ) {
        // Log if client is using an unsupported protocol version
        if version.is_none() {
            warn!(
                protocol = handshake.protocol_version,
                "Client using unsupported protocol version"
            );
        }
        // Select upstream server
        let Some(server) = self.pool.select() else {
            warn!("No available upstream servers");
            return;
        };

        // Connect to upstream
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
            "Forwarding to upstream"
        );

        // Re-send the handshake to the upstream server
        if let Err(e) = write_packet(&mut upstream, &handshake.to_raw()).await {
            error!("Failed to send handshake to upstream: {e}");
            return;
        }

        // Now forward all remaining traffic bidirectionally
        match copy_bidirectional(client, &mut upstream).await {
            Ok((to_upstream, to_client)) => {
                info!(sent = to_upstream, recv = to_client, "Session ended");
            }
            Err(e) => {
                debug!("Connection closed: {e}");
            }
        }
    }
}
