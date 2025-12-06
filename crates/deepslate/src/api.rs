//! REST API for the Deepslate control plane.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
};
use serde::{Deserialize, Serialize};

use crate::server::{Server, ServerPool};

/// Server representation in the REST API.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerDto {
    pub id: String,
    pub address: String,
    pub weight: u32,
}

/// Request to register a new server.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub id: String,
    pub address: String,
    pub weight: u32,
    pub enabled: bool,
}

/// Request to update server weight.
#[derive(Debug, Deserialize)]
pub struct UpdateWeightRequest {
    pub weight: u32,
}

/// Generic API response.
#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ApiResponse {
    const fn success() -> Self {
        Self {
            success: true,
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(message.into()),
        }
    }
}

/// Create the REST API router.
pub fn router(pool: Arc<ServerPool>) -> Router {
    Router::new()
        .route("/servers", get(list_servers))
        .route("/servers", post(register_server))
        .route("/servers/{id}", delete(deregister_server))
        .route("/servers/{id}/weight", patch(update_weight))
        .route("/servers/{id}/enable", post(enable_server))
        .route("/servers/{id}/disable", post(disable_server))
        .with_state(pool)
}

/// GET /servers - List all registered servers.
async fn list_servers(State(pool): State<Arc<ServerPool>>) -> Json<Vec<ServerDto>> {
    let servers = pool
        .list()
        .into_iter()
        .map(|s| ServerDto {
            id: s.id,
            address: s.addr,
            weight: s.weight,
        })
        .collect();

    Json(servers)
}

/// POST /servers - Register a new server.
async fn register_server(
    State(pool): State<Arc<ServerPool>>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    // Register the server
    let server = Server::new(req.id.clone(), req.address.clone(), req.weight, req.enabled);
    if pool.register(&server) {
        tracing::info!(id = %req.id, addr = %req.address, weight = req.weight, enabled = req.enabled, "Server registered");
        (StatusCode::CREATED, Json(ApiResponse::success()))
    } else {
        (
            StatusCode::CONFLICT,
            Json(ApiResponse::error(format!(
                "Server with ID '{}' already exists",
                req.id
            ))),
        )
    }
}

/// DELETE /servers/:id - Deregister a server.
async fn deregister_server(
    State(pool): State<Arc<ServerPool>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    if pool.deregister(&id).is_some() {
        tracing::info!(id = %id, "Server deregistered");
        (StatusCode::OK, Json(ApiResponse::success()))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!(
                "Server with ID '{id}' not found"
            ))),
        )
    }
}

/// PATCH /servers/:id/weight - Update server weight.
async fn update_weight(
    State(pool): State<Arc<ServerPool>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateWeightRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    pool.update_weight(&id, req.weight).map_or_else(
        || {
            (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error(format!(
                    "Server with ID '{id}' not found"
                ))),
            )
        },
        |old| {
            tracing::info!(id = %id, old, new = req.weight, "Server weight updated");
            (StatusCode::OK, Json(ApiResponse::success()))
        },
    )
}

/// POST /servers/:id/enable - Enable a server.
async fn enable_server(
    State(pool): State<Arc<ServerPool>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    if pool.update_enabled(&id, true) {
        tracing::info!(id = %id, "Server enabled");
        (StatusCode::OK, Json(ApiResponse::success()))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!(
                "Server with ID '{id}' not found"
            ))),
        )
    }
}

/// POST /servers/:id/disable - Disable a server.
async fn disable_server(
    State(pool): State<Arc<ServerPool>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    if pool.update_enabled(&id, false) {
        tracing::info!(id = %id, "Server disabled");
        (StatusCode::OK, Json(ApiResponse::success()))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!(
                "Server with ID '{id}' not found"
            ))),
        )
    }
}
