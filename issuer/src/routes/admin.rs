// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Admin API for managing the invitation system
//!
//! This module provides administrative endpoints for:
//! - Granting invites to users (reputation rewards)
//! - Banning users and their invite trees
//! - Viewing system statistics
//! - Inspecting user details and invite trees
//! - Managing bootstrap users
//!
//! # Security
//!
//! All endpoints require authentication via API key in the `X-Admin-Key` header.
//! The API key should be configured via the `ADMIN_API_KEY` environment variable.
//!
//! # Rate Limiting
//!
//! Admin endpoints have their own rate limiting separate from token issuance.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::sybil_resistance::invitation::{InvitationSystem, InvitationStats};

// ============================================================================
// State & Configuration
// ============================================================================

/// Admin API state
#[derive(Clone)]
pub struct AdminState {
    /// Reference to the invitation system
    pub invitation_system: Arc<InvitationSystem>,
    /// Admin API key for authentication
    pub api_key: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to grant invites to a user
#[derive(Debug, Deserialize)]
pub struct GrantInvitesRequest {
    /// User ID to grant invites to
    pub user_id: String,
    /// Number of invites to grant
    pub count: u32,
}

/// Response after granting invites
#[derive(Debug, Serialize)]
pub struct GrantInvitesResponse {
    pub ok: bool,
    pub user_id: String,
    pub invites_granted: u32,
    pub new_total: u32,
}

/// Request to ban a user
#[derive(Debug, Deserialize)]
pub struct BanUserRequest {
    /// User ID to ban
    pub user_id: String,
    /// Whether to ban their entire invite tree
    #[serde(default)]
    pub ban_tree: bool,
}

/// Response after banning a user
#[derive(Debug, Serialize)]
pub struct BanUserResponse {
    pub ok: bool,
    pub user_id: String,
    pub banned_count: u32,
}

/// Request to add a bootstrap user
#[derive(Debug, Deserialize)]
pub struct AddBootstrapUserRequest {
    /// User ID for the bootstrap user
    pub user_id: String,
    /// Number of invites to grant
    pub invite_count: u32,
}

/// Response after adding bootstrap user
#[derive(Debug, Serialize)]
pub struct AddBootstrapUserResponse {
    pub ok: bool,
    pub user_id: String,
    pub invites_granted: u32,
}

/// Query parameters for user lookup
#[derive(Debug, Deserialize)]
pub struct UserQuery {
    /// User ID to look up
    pub user_id: String,
}

/// Detailed user information
#[derive(Debug, Serialize)]
pub struct UserDetails {
    pub user_id: String,
    pub invites_remaining: u32,
    pub invites_sent_count: u32,
    pub invites_used_count: u32,
    pub joined_at: u64,
    pub last_invite_at: u64,
    pub reputation: f64,
    pub banned: bool,
}

/// Response containing user details
#[derive(Debug, Serialize)]
pub struct UserDetailsResponse {
    pub user: UserDetails,
    pub invitees: Vec<String>,
}

/// Stats response (wraps InvitationStats)
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub stats: InvitationStats,
    pub timestamp: u64,
}

/// Query parameters for invitation lookup
#[derive(Debug, Deserialize)]
pub struct InvitationQuery {
    /// Invitation code to look up
    pub code: String,
}

/// Invitation details
#[derive(Debug, Serialize)]
pub struct InvitationDetails {
    pub code: String,
    pub inviter_id: String,
    pub invitee_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub redeemed: bool,
}

/// Response containing invitation details
#[derive(Debug, Serialize)]
pub struct InvitationDetailsResponse {
    pub invitation: InvitationDetails,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub invitation_system_status: String,
}

// ============================================================================
// Error Types
// ============================================================================

/// Admin API errors
#[derive(Debug)]
pub enum AdminError {
    Unauthorized,
    UserNotFound(String),
    InvitationNotFound(String),
    InvalidRequest(String),
    Internal(String),
}

impl AdminError {
    fn status_code(&self) -> StatusCode {
        match self {
            AdminError::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminError::UserNotFound(_) | AdminError::InvitationNotFound(_) => {
                StatusCode::NOT_FOUND
            }
            AdminError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            AdminError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> String {
        match self {
            AdminError::Unauthorized => "unauthorized".to_string(),
            AdminError::UserNotFound(id) => format!("user not found: {}", id),
            AdminError::InvitationNotFound(code) => format!("invitation not found: {}", code),
            AdminError::InvalidRequest(msg) => format!("invalid request: {}", msg),
            AdminError::Internal(_) => "internal server error".to_string(),
        }
    }
}

impl axum::response::IntoResponse for AdminError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let message = self.message();

        // Log internal errors with details
        if matches!(self, AdminError::Internal(_)) {
            warn!("Admin API error: {:?}", self);
        }

        (
            status,
            Json(serde_json::json!({
                "error": message,
            })),
        )
            .into_response()
    }
}

// ============================================================================
// Authentication Middleware
// ============================================================================

/// Extract and verify API key from headers
fn verify_api_key(headers: &HeaderMap, expected_key: &str) -> Result<(), AdminError> {
    let provided_key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AdminError::Unauthorized)?;

    if provided_key != expected_key {
        warn!("Invalid admin API key provided");
        return Err(AdminError::Unauthorized);
    }

    Ok(())
}

// ============================================================================
// Handler Functions
// ============================================================================

/// GET /admin/health
///
/// Health check endpoint (no authentication required)
pub async fn health_handler() -> Json<HealthResponse> {
    // In a real implementation, you'd track actual uptime
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_seconds: 0, // TODO: track actual uptime
        invitation_system_status: "operational".to_string(),
    })
}

/// GET /admin/stats
///
/// Get invitation system statistics
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Response
/// ```json
/// {
///   "stats": {
///     "total_invitations": 150,
///     "redeemed_invitations": 75,
///     "pending_invitations": 75,
///     "total_users": 80,
///     "banned_users": 5
///   },
///   "timestamp": 1699454400
/// }
/// ```
pub async fn get_stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<StatsResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let stats = state.invitation_system.get_stats().await;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    info!("Admin: retrieved system stats");

    Ok(Json(StatsResponse { stats, timestamp }))
}

/// POST /admin/invites/grant
///
/// Grant invites to a user (for reputation rewards, etc.)
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Request Body
/// ```json
/// {
///   "user_id": "user123",
///   "count": 10
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "ok": true,
///   "user_id": "user123",
///   "invites_granted": 10,
///   "new_total": 15
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: Invalid or missing API key
/// - 404 Not Found: User does not exist
/// - 400 Bad Request: User is banned or invalid count
pub async fn grant_invites_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<GrantInvitesRequest>,
) -> Result<Json<GrantInvitesResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    if req.count == 0 {
        return Err(AdminError::InvalidRequest(
            "count must be greater than 0".to_string(),
        ));
    }

    // Grant the invites
    state
        .invitation_system
        .grant_invites(&req.user_id, req.count)
        .await
        .map_err(|e| {
            let err_msg = e.to_string();
            if err_msg.contains("not found") {
                AdminError::UserNotFound(req.user_id.clone())
            } else if err_msg.contains("banned") {
                AdminError::InvalidRequest(err_msg)
            } else {
                AdminError::Internal(err_msg)
            }
        })?;

    // Get the updated count (we need to query the system for this)
    // For now, we'll return a simplified response
    // TODO: Add a method to InvitationSystem to return the new total

    info!(
        user_id = %req.user_id,
        count = req.count,
        "Admin: granted invites"
    );

    Ok(Json(GrantInvitesResponse {
        ok: true,
        user_id: req.user_id,
        invites_granted: req.count,
        new_total: 0, // TODO: get actual count from system
    }))
}

/// POST /admin/users/ban
///
/// Ban a user and optionally their entire invite tree
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Request Body
/// ```json
/// {
///   "user_id": "malicious_user",
///   "ban_tree": true
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "ok": true,
///   "user_id": "malicious_user",
///   "banned_count": 15
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: Invalid or missing API key
/// - 404 Not Found: User does not exist
pub async fn ban_user_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<BanUserRequest>,
) -> Result<Json<BanUserResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    // Get stats before ban to count affected users
    let stats_before = state.invitation_system.get_stats().await;

    // Ban the user
    state
        .invitation_system
        .ban_user(&req.user_id, req.ban_tree)
        .await;

    // Get stats after ban
    let stats_after = state.invitation_system.get_stats().await;
    let banned_count = (stats_after.banned_users - stats_before.banned_users) as u32;

    info!(
        user_id = %req.user_id,
        ban_tree = req.ban_tree,
        banned_count = banned_count,
        "Admin: banned user"
    );

    Ok(Json(BanUserResponse {
        ok: true,
        user_id: req.user_id,
        banned_count,
    }))
}

/// POST /admin/bootstrap/add
///
/// Add a bootstrap user with initial invite allocation
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Request Body
/// ```json
/// {
///   "user_id": "admin_user",
///   "invite_count": 100
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "ok": true,
///   "user_id": "admin_user",
///   "invites_granted": 100
/// }
/// ```
pub async fn add_bootstrap_user_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<AddBootstrapUserRequest>,
) -> Result<Json<AddBootstrapUserResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    state
        .invitation_system
        .add_bootstrap_user(req.user_id.clone(), req.invite_count)
        .await;

    info!(
        user_id = %req.user_id,
        invite_count = req.invite_count,
        "Admin: added bootstrap user"
    );

    Ok(Json(AddBootstrapUserResponse {
        ok: true,
        user_id: req.user_id,
        invites_granted: req.invite_count,
    }))
}

/// GET /admin/users/{user_id}
///
/// Get detailed information about a user
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Response
/// ```json
/// {
///   "user": {
///     "user_id": "user123",
///     "invites_remaining": 5,
///     "invites_sent_count": 10,
///     "invites_used_count": 8,
///     "joined_at": 1699454400,
///     "last_invite_at": 1699540800,
///     "reputation": 0.95,
///     "banned": false
///   },
///   "invitees": ["user456", "user789"]
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: Invalid or missing API key
/// - 404 Not Found: User does not exist
pub async fn get_user_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<UserDetailsResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    // TODO: Add method to InvitationSystem to get user details
    // For now, return a placeholder error
    Err(AdminError::Internal(
        "get_user_details not yet implemented".to_string(),
    ))
}

/// GET /admin/invitations/{code}
///
/// Get detailed information about an invitation
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Response
/// ```json
/// {
///   "invitation": {
///     "code": "Abc123XyZ456",
///     "inviter_id": "user123",
///     "invitee_id": "user456",
///     "created_at": 1699454400,
///     "expires_at": 1702046400,
///     "redeemed": true
///   }
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: Invalid or missing API key
/// - 404 Not Found: Invitation does not exist
pub async fn get_invitation_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Result<Json<InvitationDetailsResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    // TODO: Add method to InvitationSystem to get invitation details
    // For now, return a placeholder error
    Err(AdminError::Internal(
        "get_invitation_details not yet implemented".to_string(),
    ))
}

/// POST /admin/save
///
/// Manually trigger a save of the invitation system state
///
/// # Authentication
/// Requires `X-Admin-Key` header
///
/// # Response
/// ```json
/// {
///   "ok": true,
///   "message": "State saved successfully"
/// }
/// ```
pub async fn save_state_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    state
        .invitation_system
        .save()
        .await
        .map_err(|e| AdminError::Internal(format!("Failed to save state: {}", e)))?;

    info!("Admin: manually triggered state save");

    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "State saved successfully"
    })))
}

// ============================================================================
// Router Configuration
// ============================================================================

/// Create the admin API router
///
/// # Arguments
///
/// * `invitation_system` - Arc reference to the invitation system
/// * `api_key` - Admin API key for authentication
///
/// # Returns
///
/// An Axum Router with all admin endpoints configured
pub fn admin_router(
    invitation_system: Arc<InvitationSystem>,
    api_key: String,
) -> axum::Router {
    let state = Arc::new(AdminState {
        invitation_system,
        api_key,
    });

    axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/stats", axum::routing::get(get_stats_handler))
        .route("/invites/grant", axum::routing::post(grant_invites_handler))
        .route("/users/ban", axum::routing::post(ban_user_handler))
        .route(
            "/bootstrap/add",
            axum::routing::post(add_bootstrap_user_handler),
        )
        .route("/users/:user_id", axum::routing::get(get_user_handler))
        .route(
            "/invitations/:code",
            axum::routing::get(get_invitation_handler),
        )
        .route("/save", axum::routing::post(save_state_handler))
        .with_state(state)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_error_status_codes() {
        assert_eq!(
            AdminError::Unauthorized.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AdminError::UserNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AdminError::InvalidRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AdminError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_verify_api_key() {
        let mut headers = HeaderMap::new();
        let expected_key = "test-key-123";

        // Missing key
        assert!(verify_api_key(&headers, expected_key).is_err());

        // Wrong key
        headers.insert("x-admin-key", "wrong-key".parse().unwrap());
        assert!(verify_api_key(&headers, expected_key).is_err());

        // Correct key
        headers.insert("x-admin-key", expected_key.parse().unwrap());
        assert!(verify_api_key(&headers, expected_key).is_ok());
    }
}