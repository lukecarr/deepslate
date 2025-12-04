//! L4 TCP proxy logic for forwarding connections to upstream servers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, error, info, info_span};

use crate::server::ServerPool;

/// L4 proxy that forwards TCP connections to upstream servers.
pub struct Proxy {
    /// Pool of upstream servers
    pool: Arc<ServerPool>,
    /// Session counter for logging
    session_counter: AtomicUsize,
}

impl Proxy {
    /// Create a new proxy with the given server pool.
    #[must_use]
    pub const fn new(pool: Arc<ServerPool>) -> Self {
        Self {
            pool,
            session_counter: AtomicUsize::new(0),
        }
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

        // Select upstream server
        let Some(server) = self.pool.select() else {
            error!(
                sid = session_id,
                ip = %client_addr.ip(),
                "No available upstream servers"
            );
            return;
        };

        async {
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
                "Established"
            );

            match copy_bidirectional(&mut client, &mut upstream).await {
                Ok((to_upstream, to_client)) => {
                    info!(sent = to_upstream, recv = to_client, "Session ended");
                }
                Err(e) => {
                    error!("Proxy error: {e}");
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
}
