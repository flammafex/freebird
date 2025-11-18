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
//! - Managing key rotation
//!
//! # Security
//!
//! All endpoints require authentication via API key in the `X-Admin-Key` header.
//! The API key should be configured via the `ADMIN_API_KEY` environment variable.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashSet;
use tracing::{info, warn};
use crate::multi_key_voprf::{KeyInfo, KeyStats, MultiKeyVoprfCore};
use crate::sybil_resistance::invitation::{InvitationSystem, InvitationStats};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
// ============================================================================
// State & Configuration
// ============================================================================

// Admin API state
#[derive(Clone)]
pub struct AdminState {
    /// Reference to the invitation system
    pub invitation_system: Arc<InvitationSystem>,
    /// Reference to the multi-key VOPRF core
    pub multi_key_voprf: Arc<MultiKeyVoprfCore>,
    /// Admin API key for authentication
    pub api_key: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to grant invites to a user
#[derive(Debug, Deserialize)]
pub struct GrantInvitesRequest {
    pub user_id: String,
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
    pub user_id: String,
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
    pub user_id: String,
    pub invite_count: u32,
}

/// Response after adding bootstrap user
#[derive(Debug, Serialize)]
pub struct AddBootstrapUserResponse {
    pub ok: bool,
    pub user_id: String,
    pub invites_granted: u32,
}

/// Stats response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub stats: InvitationStats,
    pub timestamp: u64,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub invitation_system_status: String,
}

/// Request to rotate to a new key
#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub new_kid: String,
    #[serde(default)]
    pub grace_period_secs: Option<u64>,
}

/// Response after key rotation
#[derive(Debug, Serialize)]
pub struct RotateKeyResponse {
    pub ok: bool,
    pub old_kid: String,
    pub new_kid: String,
    pub grace_period_secs: u64,
    pub expires_at: u64,
}

/// Response with list of all keys
#[derive(Debug, Serialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyInfo>,
    pub stats: KeyStats,
}

/// Response after cleanup
#[derive(Debug, Serialize)]
pub struct CleanupKeysResponse {
    pub ok: bool,
    pub removed_count: usize,
    pub removed_kids: Vec<String>,
}

/// Response after force removing a key
#[derive(Debug, Serialize)]
pub struct ForceRemoveKeyResponse {
    pub ok: bool,
    pub kid: String,
    pub message: String,
}

// ============================================================================
// Error Types
// ============================================================================

/// Admin API errors
#[derive(Debug)]
pub enum AdminError {
    Unauthorized,
    UserNotFound(String),
    InvalidRequest(String),
    Internal(String),
}

impl AdminError {
    fn status_code(&self) -> StatusCode {
        match self {
            AdminError::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminError::UserNotFound(_) => StatusCode::NOT_FOUND,
            AdminError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            AdminError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> String {
        match self {
            AdminError::Unauthorized => "unauthorized".to_string(),
            AdminError::UserNotFound(id) => format!("user not found: {}", id),
            AdminError::InvalidRequest(msg) => format!("invalid request: {}", msg),
            AdminError::Internal(_) => "internal server error".to_string(),
        }
    }
}

impl axum::response::IntoResponse for AdminError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let message = self.message();

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
// Authentication
// ============================================================================

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
// Invitation System Handlers
// ============================================================================

pub async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_seconds: 0,
        invitation_system_status: "operational".to_string(),
    })
}

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

    info!(
        user_id = %req.user_id,
        count = req.count,
        "Admin: granted invites"
    );

    Ok(Json(GrantInvitesResponse {
        ok: true,
        user_id: req.user_id,
        invites_granted: req.count,
        new_total: 0,
    }))
}

pub async fn ban_user_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<BanUserRequest>,
) -> Result<Json<BanUserResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let stats_before = state.invitation_system.get_stats().await;

    state
        .invitation_system
        .ban_user(&req.user_id, req.ban_tree)
        .await;

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
// Key Management Handlers
// ============================================================================

pub async fn list_keys_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<ListKeysResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let keys = state.multi_key_voprf.list_keys().await;
    let stats = state.multi_key_voprf.key_stats().await;

    info!("Admin: listed keys (count={})", keys.len());

    Ok(Json(ListKeysResponse { keys, stats }))
}

pub async fn rotate_key_handler(  // <-- MUST have 'async' keyword
    State(state): State<Arc<AdminState>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<RotateKeyResponse>, AdminError> {
    if req.new_kid.is_empty() {
        return Err(AdminError::InvalidRequest(
            "new_kid cannot be empty".to_string(),
        ));
    }

    let old_kid = state.multi_key_voprf.active_kid().await;

    let signing_key = SigningKey::random(&mut OsRng);
    let sk_bytes: [u8; 32] = signing_key.to_bytes().into();
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_encoded_point(true);
    let pubkey_b64 = base64ct::Base64UrlUnpadded::encode_string(pubkey_bytes.as_bytes());

    let grace_period = req.grace_period_secs.unwrap_or(30 * 24 * 3600);
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + grace_period;

    state
        .multi_key_voprf
        .rotate_key(sk_bytes, pubkey_b64, req.new_kid.clone(), Some(grace_period))
        .await
        .map_err(|e| AdminError::Internal(format!("Key rotation failed: {}", e)))?;

    info!(old_kid = %old_kid, new_kid = %req.new_kid, "Admin: rotated key");

    Ok(Json(RotateKeyResponse {
        ok: true,
        old_kid,
        new_kid: req.new_kid,
        grace_period_secs: grace_period,
        expires_at,
    }))
}
pub async fn cleanup_keys_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<CleanupKeysResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let keys_before = state.multi_key_voprf.list_keys().await;
    
    let removed_count = state
        .multi_key_voprf
        .cleanup_expired_keys()
        .await
        .map_err(|e| AdminError::Internal(format!("Cleanup failed: {}", e)))?;

    let keys_after = state.multi_key_voprf.list_keys().await;
    let remaining_kids: HashSet<_> = 
        keys_after.iter().map(|k| k.kid.clone()).collect();
    
    let removed_kids: Vec<String> = keys_before
        .iter()
        .filter(|k| !remaining_kids.contains(&k.kid))
        .map(|k| k.kid.clone())
        .collect();

    info!(
        removed_count = removed_count,
        "Admin: cleaned up expired keys"
    );

    Ok(Json(CleanupKeysResponse {
        ok: true,
        removed_count,
        removed_kids,
    }))
}

pub async fn force_remove_key_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(kid): Path<String>,
) -> Result<Json<ForceRemoveKeyResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let active_kid = state.multi_key_voprf.active_kid().await;
    if kid == active_kid {
        return Err(AdminError::InvalidRequest(
            "Cannot remove active key. Rotate to a new key first.".to_string(),
        ));
    }

    state
        .multi_key_voprf
        .force_remove_key(&kid)
        .await
        .map_err(|e| {
            let err_msg = e.to_string();
            if err_msg.contains("not found") {
                AdminError::UserNotFound(kid.clone())
            } else {
                AdminError::Internal(err_msg)
            }
        })?;

    warn!(kid = %kid, "Admin: forcibly removed key");

    Ok(Json(ForceRemoveKeyResponse {
        ok: true,
        kid,
        message: "Key forcibly removed. Tokens issued with this key are now invalid.".to_string(),
    }))
}

// ============================================================================
// Router Configuration
// ============================================================================

pub fn admin_router(
    invitation_system: Arc<InvitationSystem>,
    multi_key_voprf: Arc<MultiKeyVoprfCore>,
    api_key: String,
) -> axum::Router {
    let state = Arc::new(AdminState {
        invitation_system,
        multi_key_voprf,
        api_key,
    });

    axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/stats", axum::routing::get(get_stats_handler))
        .route("/invites/grant", axum::routing::post(grant_invites_handler))
        .route("/users/ban", axum::routing::post(ban_user_handler))
        .route("/bootstrap/add", axum::routing::post(add_bootstrap_user_handler))
        .route("/save", axum::routing::post(save_state_handler))
        .route("/keys", axum::routing::get(list_keys_handler))
        .route("/keys/rotate", axum::routing::post(rotate_key_handler))
        .route("/keys/cleanup", axum::routing::post(cleanup_keys_handler))
        .route("/keys/:kid", axum::routing::delete(force_remove_key_handler))
        .with_state(state)
}