//! Deepslate: L4 load balancer for Minecraft proxy server blue-green deployments

mod api;
mod proxy;
mod rpc;
mod server;
mod utils;

use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::Server as TonicServer;
use tracing::{debug, error, info};

use crate::proxy::Proxy;
use crate::rpc::DeepslateService;
use crate::rpc::proto::deepslate_server::DeepslateServer;
use crate::server::{Server, ServerPool};
use crate::utils::env_bool;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let log_filter = tracing_subscriber::EnvFilter::new(
        std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
    );

    let json_logging = std::env::var("LOG_JSON")
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);

    if json_logging {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(log_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(log_filter)
            .init();
    }

    // Create server pool
    let pool = Arc::new(ServerPool::new());

    // Register default servers (for backwards compatibility during development)
    // In production, servers would register themselves via the control plane
    pool.register(&Server::new("blue", "blue:25565", 100));
    pool.register(&Server::new("green", "green:25565", 100));

    // Parse configuration
    let grpc_enabled = env_bool("GRPC_ENABLED", true)?;
    let rest_enabled = env_bool("REST_ENABLED", true)?;

    if !grpc_enabled {
        debug!("gRPC control plane disabled via GRPC_ENABLED=false");
    }
    let grpc_addr = std::env::var("GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:25577".to_string());
    
    if !rest_enabled {
        debug!("REST control plane disabled via REST_ENABLED=false");
    }
    let rest_addr = std::env::var("REST_ADDR").unwrap_or_else(|_| "0.0.0.0:25578".to_string());

    // Pre-bind the proxy listener to fail fast on port conflicts
    let proxy_addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:25565".to_string());
    let proxy_listener = TcpListener::bind(&proxy_addr).await?;
    info!("Proxy listening on {proxy_addr}");

    // Create the proxy
    let proxy = Arc::new(Proxy::new(Arc::clone(&pool)));

    // Run all servers concurrently - exit if any fails
    tokio::select! {
        result = run_grpc_server(&grpc_addr, Arc::clone(&pool)), if grpc_enabled => {
            error!("gRPC server exited unexpectedly");
            result?;
        }
        result = run_rest_server(&rest_addr, Arc::clone(&pool)), if rest_enabled => {
            error!("REST server exited unexpectedly");
            result?;
        }
        () = proxy.run(proxy_listener) => {
            error!("Proxy exited unexpectedly");
        }
    }

    Ok(())
}

/// Run the gRPC control plane server.
async fn run_grpc_server(addr: &str, pool: Arc<ServerPool>) -> Result<(), BoxError> {
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
async fn run_rest_server(addr: &str, pool: Arc<ServerPool>) -> Result<(), BoxError> {
    let listener = TcpListener::bind(addr).await?;
    let router = api::router(pool);

    info!("REST control plane listening on {addr}");

    axum::serve(listener, router).await?;

    Ok(())
}
