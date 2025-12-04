//! Deepslate: L4 load balancer for Minecraft proxy server blue-green deployments

mod api;
mod proxy;
mod rpc;
mod server;

use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::Server as TonicServer;
use tracing::info;

use crate::proxy::Proxy;
use crate::rpc::DeepslateService;
use crate::rpc::proto::deepslate_server::DeepslateServer;
use crate::server::{Server, ServerPool};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Create server pool
    let pool = Arc::new(ServerPool::new());

    // Register default servers (for backwards compatibility during development)
    // In production, servers would register themselves via the control plane
    pool.register(Server::new("blue", "blue:25565", 100));
    pool.register(Server::new("green", "green:25565", 100));

    info!("Registered {} upstream server(s)", pool.len());

    // Start the gRPC control plane
    let grpc_addr = std::env::var("GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:25577".to_string());
    let grpc_pool = Arc::clone(&pool);
    tokio::spawn(async move {
        if let Err(e) = run_grpc_server(&grpc_addr, grpc_pool).await {
            tracing::error!("gRPC server error: {e}");
        }
    });

    // Start the REST API
    let rest_addr = std::env::var("REST_ADDR").unwrap_or_else(|_| "0.0.0.0:25578".to_string());
    let rest_pool = Arc::clone(&pool);
    tokio::spawn(async move {
        if let Err(e) = run_rest_server(&rest_addr, rest_pool).await {
            tracing::error!("REST server error: {e}");
        }
    });

    // Start the L4 proxy
    let proxy = Arc::new(Proxy::new(Arc::clone(&pool)));
    let listen_addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:25565".to_string());
    let listener = TcpListener::bind(&listen_addr).await?;

    info!("Proxy listening on {listen_addr}");

    proxy.run(listener).await;

    Ok(())
}

/// Run the gRPC control plane server.
async fn run_grpc_server(
    addr: &str,
    pool: Arc<ServerPool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = addr.parse()?;
    let service = DeepslateServer::new(DeepslateService::new(pool));

    info!("gRPC control plane listening on {addr}");

    TonicServer::builder()
        .add_service(service)
        .serve(addr)
        .await?;

    Ok(())
}

/// Run the REST API server.
async fn run_rest_server(
    addr: &str,
    pool: Arc<ServerPool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let router = api::router(pool);

    info!("REST control plane listening on {addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
