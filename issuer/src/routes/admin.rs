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

use crate::multi_key_voprf::{KeyInfo, KeyStats, MultiKeyVoprfCore};
use crate::sybil_resistance::invitation::{InvitationStats, InvitationSystem};
use axum::{
    extract::{Path, State, Query},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    Json,
};
use base64ct::Encoding;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};
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
    /// Reference to the federation store
    pub federation_store: crate::federation_store::FederationStore,
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

/// Request to register the owner of this Freebird instance
#[derive(Debug, Deserialize)]
pub struct RegisterOwnerRequest {
    pub user_id: String,
}

/// Response after registering owner
#[derive(Debug, Serialize)]
pub struct RegisterOwnerResponse {
    pub success: bool,
    pub owner: String,
}

/// Request to create invitations
#[derive(Debug, Deserialize)]
pub struct CreateInvitationsRequest {
    pub inviter_id: String,
    pub count: u32,
}

/// Single invitation code with signature
#[derive(Debug, Serialize)]
pub struct InvitationCode {
    pub code: String,
    pub signature: String,
    pub expires_at: u64,
}

/// Response after creating invitations
#[derive(Debug, Serialize)]
pub struct CreateInvitationsResponse {
    pub ok: bool,
    pub inviter_id: String,
    pub invitations: Vec<InvitationCode>,
}

/// Stats response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub stats: InvitationStats,
    pub timestamp: u64,
    /// Owner of this Freebird instance (if registered)
    pub owner: Option<String>,
    /// Count of unique users who have redeemed invitations
    pub user_count: usize,
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

/// Request to add a vouch
#[derive(Debug, Deserialize)]
pub struct AddVouchRequest {
    pub vouch: freebird_common::federation::Vouch,
}

/// Request to add a revocation
#[derive(Debug, Deserialize)]
pub struct AddRevocationRequest {
    pub revocation: freebird_common::federation::Revocation,
}

/// Response for vouch operations
#[derive(Debug, Serialize)]
pub struct VouchResponse {
    pub ok: bool,
    pub message: String,
}

/// Response for revocation operations
#[derive(Debug, Serialize)]
pub struct RevocationResponse {
    pub ok: bool,
    pub message: String,
}

/// User summary for list view
#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub user_id: String,
    pub invites_remaining: u32,
    pub banned: bool,
}

/// Detailed user response
#[derive(Debug, Serialize)]
pub struct UserDetailsResponse {
    pub user_id: String,
    pub invites_remaining: u32,
    pub invites_sent: Vec<String>,
    pub invites_used: Vec<String>,
    pub joined_at: u64,
    pub last_invite_at: u64,
    pub reputation: f64,
    pub banned: bool,
    pub invitees: Vec<String>,
}

/// Parameters for listing invitations
#[derive(Debug, Deserialize)]
pub struct ListInvitationsParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize { 50 }

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
// UI Handler
// ============================================================================

/// Serve the admin UI
pub async fn admin_ui_handler() -> impl IntoResponse {
    const ADMIN_UI_HTML: &str = include_str!("../admin_ui/index.html");
    Html(ADMIN_UI_HTML)
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
    let owner = state.invitation_system.get_owner().await;
    let user_count = state.invitation_system.get_redeemed_user_count().await;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    info!("Admin: retrieved system stats");

    Ok(Json(StatsResponse {
        stats,
        timestamp,
        owner,
        user_count,
    }))
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

/// Register the owner of this Freebird instance
///
/// This endpoint allows registering a user as the "owner" of the Freebird instance.
/// This is used by Clout to tie the instance to its founding user.
///
/// Only the first registration succeeds - subsequent calls will fail.
pub async fn register_owner_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterOwnerRequest>,
) -> Result<Json<RegisterOwnerResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    if req.user_id.is_empty() {
        return Err(AdminError::InvalidRequest(
            "user_id cannot be empty".to_string(),
        ));
    }

    state
        .invitation_system
        .set_owner(req.user_id.clone())
        .await
        .map_err(|e| {
            let err_msg = e.to_string();
            if err_msg.contains("already registered") {
                AdminError::InvalidRequest("owner already registered".to_string())
            } else {
                AdminError::Internal(err_msg)
            }
        })?;

    info!(
        owner = %req.user_id,
        "Admin: registered instance owner"
    );

    Ok(Json(RegisterOwnerResponse {
        success: true,
        owner: req.user_id,
    }))
}

pub async fn create_invitations_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<CreateInvitationsRequest>,
) -> Result<Json<CreateInvitationsResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    if req.count == 0 {
        return Err(AdminError::InvalidRequest(
            "count must be greater than 0".to_string(),
        ));
    }

    if req.count > 100 {
        return Err(AdminError::InvalidRequest(
            "count cannot exceed 100 per request".to_string(),
        ));
    }

    let mut invitations = Vec::new();

    for _ in 0..req.count {
        // Use admin version to bypass rate limits (cooldown, waiting period)
        match state.invitation_system.generate_invite_admin(&req.inviter_id).await {
            Ok((code, signature, expires_at)) => {
                invitations.push(InvitationCode {
                    code,
                    signature: hex::encode(signature),
                    expires_at,
                });
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("not found") {
                    return Err(AdminError::UserNotFound(req.inviter_id.clone()));
                } else if err_msg.contains("banned") {
                    return Err(AdminError::InvalidRequest(format!(
                        "User {} is banned",
                        req.inviter_id
                    )));
                } else if err_msg.contains("no invites remaining") {
                    return Err(AdminError::InvalidRequest(format!(
                        "User {} has no invites remaining",
                        req.inviter_id
                    )));
                } else if err_msg.contains("cooldown") {
                    return Err(AdminError::InvalidRequest(format!(
                        "User {} is in cooldown period",
                        req.inviter_id
                    )));
                } else {
                    return Err(AdminError::Internal(err_msg));
                }
            }
        }
    }

    info!(
        inviter_id = %req.inviter_id,
        count = req.count,
        "Admin: created invitations"
    );

    Ok(Json(CreateInvitationsResponse {
        ok: true,
        inviter_id: req.inviter_id,
        invitations,
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

pub async fn list_users_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserSummary>>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let users = state.invitation_system.list_users().await;
    let summaries = users
        .into_iter()
        .map(|(user_id, invites_remaining, banned)| UserSummary {
            user_id,
            invites_remaining,
            banned,
        })
        .collect();

    info!("Admin: listed users");
    Ok(Json(summaries))
}

pub async fn get_user_details_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<UserDetailsResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let (details, invitees) = state
        .invitation_system
        .get_user_details(&user_id)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                AdminError::UserNotFound(user_id.clone())
            } else {
                AdminError::Internal(msg)
            }
        })?;

    Ok(Json(UserDetailsResponse {
        user_id: details.user_id,
        invites_remaining: details.invites_remaining,
        invites_sent: details.invites_sent,
        invites_used: details.invites_used,
        joined_at: details.joined_at,
        last_invite_at: details.last_invite_at,
        reputation: details.reputation,
        banned: details.banned,
        invitees,
    }))
}

pub async fn list_invitations_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(params): Query<ListInvitationsParams>,
) -> Result<Json<Vec<crate::sybil_resistance::invitation::Invitation>>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let invites = state.invitation_system.list_invitations(params.limit).await;
    info!("Admin: listed recent invitations (count={})", invites.len());

    Ok(Json(invites))
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

pub async fn rotate_key_handler(
    // <-- MUST have 'async' keyword
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
        .as_secs()
        + grace_period;

    state
        .multi_key_voprf
        .rotate_key(
            sk_bytes,
            pubkey_b64,
            req.new_kid.clone(),
            Some(grace_period),
        )
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
    let remaining_kids: HashSet<_> = keys_after.iter().map(|k| k.kid.clone()).collect();

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
// Federation Management Handlers
// ============================================================================

/// Add a vouch to the federation store
async fn add_vouch_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<AddVouchRequest>,
) -> Result<Json<VouchResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    state
        .federation_store
        .add_vouch(req.vouch.clone())
        .await
        .map_err(|e| AdminError::InvalidRequest(e.to_string()))?;

    info!("Admin: added vouch for {}", req.vouch.vouched_issuer_id);

    Ok(Json(VouchResponse {
        ok: true,
        message: format!("Vouch for {} added successfully", req.vouch.vouched_issuer_id),
    }))
}

/// Remove a vouch from the federation store
async fn remove_vouch_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
) -> Result<Json<VouchResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    state
        .federation_store
        .remove_vouch(&issuer_id)
        .await
        .map_err(|e| AdminError::UserNotFound(e.to_string()))?;

    info!("Admin: removed vouch for {}", issuer_id);

    Ok(Json(VouchResponse {
        ok: true,
        message: format!("Vouch for {} removed successfully", issuer_id),
    }))
}

/// List all vouches
async fn list_vouches_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<freebird_common::federation::Vouch>>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let vouches = state.federation_store.get_vouches().await;

    Ok(Json(vouches))
}

/// Add a revocation to the federation store
async fn add_revocation_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<AddRevocationRequest>,
) -> Result<Json<RevocationResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    state
        .federation_store
        .add_revocation(req.revocation.clone())
        .await
        .map_err(|e| AdminError::InvalidRequest(e.to_string()))?;

    info!("Admin: added revocation for {}", req.revocation.revoked_issuer_id);

    Ok(Json(RevocationResponse {
        ok: true,
        message: format!("Revocation for {} added successfully", req.revocation.revoked_issuer_id),
    }))
}

/// Remove a revocation from the federation store
async fn remove_revocation_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
) -> Result<Json<RevocationResponse>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    state
        .federation_store
        .remove_revocation(&issuer_id)
        .await
        .map_err(|e| AdminError::UserNotFound(e.to_string()))?;

    info!("Admin: removed revocation for {}", issuer_id);

    Ok(Json(RevocationResponse {
        ok: true,
        message: format!("Revocation for {} removed successfully", issuer_id),
    }))
}

/// List all revocations
async fn list_revocations_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<freebird_common::federation::Revocation>>, AdminError> {
    verify_api_key(&headers, &state.api_key)?;

    let revocations = state.federation_store.get_revocations().await;

    Ok(Json(revocations))
}

// ============================================================================
// Router Configuration
// ============================================================================

pub fn admin_router(
    invitation_system: Arc<InvitationSystem>,
    multi_key_voprf: Arc<MultiKeyVoprfCore>,
    federation_store: crate::federation_store::FederationStore,
    api_key: String,
) -> axum::Router {
    let state = Arc::new(AdminState {
        invitation_system,
        multi_key_voprf,
        federation_store,
        api_key,
    });

    axum::Router::new()
        .route("/", axum::routing::get(admin_ui_handler))
        .route("/health", axum::routing::get(health_handler))
        .route("/stats", axum::routing::get(get_stats_handler))
        .route("/users", axum::routing::get(list_users_handler)) // <-- New
        .route("/users/:user_id", axum::routing::get(get_user_details_handler)) // <-- New
        .route("/invites/grant", axum::routing::post(grant_invites_handler))
        .route("/invitations", axum::routing::get(list_invitations_handler))
        .route("/invitations/create", axum::routing::post(create_invitations_handler))
        .route("/users/ban", axum::routing::post(ban_user_handler))
        .route(
            "/bootstrap/add",
            axum::routing::post(add_bootstrap_user_handler),
        )
        .route(
            "/register-owner",
            axum::routing::post(register_owner_handler),
        )
        .route("/save", axum::routing::post(save_state_handler))
        .route("/keys", axum::routing::get(list_keys_handler))
        .route("/keys/rotate", axum::routing::post(rotate_key_handler))
        .route("/keys/cleanup", axum::routing::post(cleanup_keys_handler))
        .route(
            "/keys/:kid",
            axum::routing::delete(force_remove_key_handler),
        )
        // Federation management routes
        .route("/federation/vouches", axum::routing::get(list_vouches_handler))
        .route("/federation/vouches", axum::routing::post(add_vouch_handler))
        .route("/federation/vouches/:issuer_id", axum::routing::delete(remove_vouch_handler))
        .route("/federation/revocations", axum::routing::get(list_revocations_handler))
        .route("/federation/revocations", axum::routing::post(add_revocation_handler))
        .route("/federation/revocations/:issuer_id", axum::routing::delete(remove_revocation_handler))
        .with_state(state)
}
