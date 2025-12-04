use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

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
    fn select_upstream(&self) -> &str {
        let idx = self.connection_count.fetch_add(1, Ordering::SeqCst) % self.upstreams.len();
        &self.upstreams[idx]
    }

    /// Handle a single client connection.
    async fn handle_connection(&self, mut client: TcpStream, client_addr: SocketAddr) {
        let upstream_addr = self.select_upstream();

        info!("{client_addr} -> routing to {upstream_addr}");

        let mut upstream = match TcpStream::connect(upstream_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    "Failed to connect to upstream {upstream_addr} for client {client_addr}: {e}"
                );
                return;
            }
        };

        info!("{client_addr} <-> {upstream_addr} established");

        match copy_bidirectional(&mut client, &mut upstream).await {
            Ok((to_upstream, to_client)) => {
                info!("{client_addr} session ended (sent: {to_upstream}, received: {to_client})");
            }
            Err(e) => {
                error!("Proxy error {client_addr} <-> {upstream_addr}: {e}");
            }
        }
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
