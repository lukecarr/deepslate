use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, error, info, info_span};

/// Deepslate: L4 load balancer for Minecraft proxy server blue-green deployments
///
/// This is a pure TCP proxy that forwards raw bytes between clients and upstream
/// Velocity proxy servers using round-robin load balancing.
struct Deepslate {
    /// Upstream server addresses
    upstreams: Vec<String>,
    /// Connection counter for round-robin selection
    connection_count: AtomicUsize,
}

impl Deepslate {
    /// Create a new Deepslate instance, with the given upstream server addresses.
    /// Returns `None` if upstreams is empty.
    fn new(upstreams: Vec<String>) -> Option<Self> {
        if upstreams.is_empty() {
            return None;
        }
        Some(Self {
            upstreams,
            connection_count: AtomicUsize::new(0),
        })
    }

    /// Select the next upstream server using round-robin.
    /// Returns (`session_id`, `upstream_addr`).
    fn select_upstream(&self) -> (usize, &str) {
        let idx = self.connection_count.fetch_add(1, Ordering::SeqCst);
        (idx, &self.upstreams[idx % self.upstreams.len()])
    }

    /// Handle a single client connection.
    async fn handle_connection(&self, mut client: TcpStream, client_addr: SocketAddr) {
        let (session_id, upstream_addr) = self.select_upstream();

        async {
            let mut upstream = match TcpStream::connect(upstream_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!(upstream = upstream_addr, "Failed to connect: {e}");
                    return;
                }
            };

            info!(upstream = upstream_addr, "Established");

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let upstreams = vec!["blue:25565".to_string(), "green:25565".to_string()];

    let deepslate =
        Arc::new(Deepslate::new(upstreams).ok_or("At least one upstream server is required")?);

    let listen_addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:25565".to_string());
    let listener = TcpListener::bind(&listen_addr).await?;

    info!("Listening on {listen_addr}");

    loop {
        match listener.accept().await {
            Ok((client, client_addr)) => {
                let deepslate = Arc::clone(&deepslate);

                tokio::spawn(async move {
                    deepslate.handle_connection(client, client_addr).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {e}");
            }
        }
    }
}
