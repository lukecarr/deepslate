//! gRPC service implementation for the Deepslate control plane.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::server::{Server, ServerPool};

// Include the generated protobuf code
pub mod proto {
    #![allow(clippy::doc_markdown)]
    #![allow(clippy::default_trait_access)]
    #![allow(clippy::missing_const_for_fn)]
    #![allow(clippy::too_many_lines)]
    #![allow(clippy::derive_partial_eq_without_eq)]

    tonic::include_proto!("deepslate");
}

use proto::deepslate_server::Deepslate;
use proto::{
    DeregisterServerRequest, DeregisterServerResponse, DisableServerRequest, DisableServerResponse,
    EnableServerRequest, EnableServerResponse, ListServersRequest, ListServersResponse,
    RegisterServerRequest, RegisterServerResponse, UpdateWeightRequest, UpdateWeightResponse,
};

/// gRPC service implementation.
pub struct DeepslateService {
    pool: Arc<ServerPool>,
}

impl DeepslateService {
    /// Create a new gRPC service with the given server pool.
    #[must_use]
    pub const fn new(pool: Arc<ServerPool>) -> Self {
        Self { pool }
    }
}

#[tonic::async_trait]
impl Deepslate for DeepslateService {
    async fn register_server(
        &self,
        request: Request<RegisterServerRequest>,
    ) -> Result<Response<RegisterServerResponse>, Status> {
        let req = request.into_inner();

        // Create and register the server
        let server = Server::new(req.id.clone(), req.address.clone(), req.weight, req.enabled);
        if self.pool.register(&server) {
            tracing::info!(id = %req.id, addr = %req.address, weight = req.weight, enabled = req.enabled, "Server registered");
            Ok(Response::new(RegisterServerResponse {
                success: true,
                error: String::new(),
            }))
        } else {
            Ok(Response::new(RegisterServerResponse {
                success: false,
                error: format!("Server with ID '{}' already exists", req.id),
            }))
        }
    }

    async fn deregister_server(
        &self,
        request: Request<DeregisterServerRequest>,
    ) -> Result<Response<DeregisterServerResponse>, Status> {
        let req = request.into_inner();

        if self.pool.deregister(&req.id).is_some() {
            tracing::info!(id = %req.id, "Server deregistered");
            Ok(Response::new(DeregisterServerResponse {
                success: true,
                error: String::new(),
            }))
        } else {
            Ok(Response::new(DeregisterServerResponse {
                success: false,
                error: format!("Server with ID '{}' not found", req.id),
            }))
        }
    }

    async fn update_weight(
        &self,
        request: Request<UpdateWeightRequest>,
    ) -> Result<Response<UpdateWeightResponse>, Status> {
        let req = request.into_inner();

        if let Some(old) = self.pool.update_weight(&req.id, req.weight) {
            tracing::info!(id = %req.id, old = old, new = req.weight, "Server weight updated");
            Ok(Response::new(UpdateWeightResponse {
                success: true,
                error: String::new(),
            }))
        } else {
            Ok(Response::new(UpdateWeightResponse {
                success: false,
                error: format!("Server with ID '{}' not found", req.id),
            }))
        }
    }

    async fn list_servers(
        &self,
        _request: Request<ListServersRequest>,
    ) -> Result<Response<ListServersResponse>, Status> {
        let servers = self
            .pool
            .list()
            .into_iter()
            .map(|s| proto::Server {
                id: s.id,
                address: s.addr,
                weight: s.weight,
                enabled: s.enabled,
            })
            .collect();

        Ok(Response::new(ListServersResponse { servers }))
    }

    async fn enable_server(
        &self,
        request: Request<EnableServerRequest>,
    ) -> Result<Response<EnableServerResponse>, Status> {
        let req = request.into_inner();

        if self.pool.update_enabled(&req.id, true) {
            tracing::info!(id = %req.id, "Server enabled");
        }
        Ok(Response::new(EnableServerResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn disable_server(
        &self,
        request: Request<DisableServerRequest>,
    ) -> Result<Response<DisableServerResponse>, Status> {
        let req = request.into_inner();

        if self.pool.update_enabled(&req.id, false) {
            tracing::info!(id = %req.id, "Server disabled");
        }
        Ok(Response::new(DisableServerResponse {
            success: true,
            error: String::new(),
        }))
    }
}
