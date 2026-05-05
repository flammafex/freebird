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

use crate::audit::{AuditEntry, AuditLog};
use crate::multi_key_voprf::{KeyInfo, KeyStats, MultiKeyVoprfCore};
use crate::routes::admin_rate_limit::AdminRateLimiter;
use crate::sybil_resistance::invitation::{InvitationFilter, InvitationStats, InvitationSystem};
use crate::sybil_resistance::multi_party_vouching::{
    MultiPartyVouchingSystem, PendingVouchSummary, VoucherSummary,
};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    Json,
};
use base64ct::Encoding;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
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
    /// Optional multi-party vouching system
    pub multi_party_vouching: Option<Arc<MultiPartyVouchingSystem>>,
    /// Reference to the multi-key VOPRF core
    pub multi_key_voprf: Arc<MultiKeyVoprfCore>,
    /// Reference to the audit log
    pub audit_log: Arc<AuditLog>,
    /// Admin API key for authentication
    pub api_key: String,
    /// Session signing key derived from API key via HKDF
    pub session_key: [u8; 32],
    /// Rate limiter for authentication attempts
    pub rate_limiter: AdminRateLimiter,
    /// Whether running behind a proxy (use X-Forwarded-For)
    pub behind_proxy: bool,
    /// Whether TLS is required (affects Secure cookie flag)
    pub require_tls: bool,
    /// Optional WebAuthn credential store (only if webauthn feature enabled)
    #[cfg(feature = "human-gate-webauthn")]
    pub webauthn_store: Option<crate::webauthn::CredentialStore>,
    /// Configuration summary for the admin API
    pub config_summary: ConfigSummary,
}

/// Derive a session signing key from the admin API key using HKDF-SHA256.
fn derive_session_key(api_key: &str) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hkdf = Hkdf::<Sha256>::new(Some(b"freebird-session-salt"), api_key.as_bytes());
    let mut session_key = [0u8; 32];
    hkdf.expand(b"freebird-admin-session-v1", &mut session_key)
        .expect("HKDF expand should not fail for 32 bytes");
    session_key
}

/// Compute a session token (HMAC of a fixed message with the session key).
fn compute_session_token(session_key: &[u8; 32]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(session_key).unwrap();
    mac.update(b"freebird-admin-session-valid");
    base64ct::Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes())
}

/// Verify a session token against the session key.
fn verify_session_token(session_key: &[u8; 32], token: &str) -> bool {
    let expected = compute_session_token(session_key);
    constant_time_key_verify(&expected, token)
}

/// Extract session cookie value from headers.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(token) = part.strip_prefix("freebird_session=") {
                    return Some(token.to_string());
                }
            }
        }
    }
    None
}

/// Sanitized configuration summary (no secrets)
#[derive(Clone, Debug)]
pub struct ConfigSummary {
    pub issuer_id: String,
    pub sybil_config: SybilConfigSummary,
    pub epoch_duration_secs: u64,
    pub epoch_retention: u32,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub webauthn_enabled: bool,
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

/// Request to unban a user
#[derive(Debug, Deserialize)]
pub struct UnbanUserRequest {
    pub user_id: String,
}

/// Response after unbanning a user
#[derive(Debug, Serialize)]
pub struct UnbanUserResponse {
    pub ok: bool,
    pub user_id: String,
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
    /// Service type identifier for UI detection ("issuer" or "verifier")
    pub service: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub invitation_system_status: String,
}

/// Sybil configuration summary (sanitized - no secrets)
#[derive(Debug, Clone, Serialize)]
pub struct SybilConfigSummary {
    /// Current Sybil resistance mode
    pub mode: String,
    /// Human-readable description of the mode
    pub mode_description: String,
    /// Configuration details specific to the current mode
    pub settings: SybilModeSettings,
    /// Combined mode mechanisms (only if mode is "combined")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub combined_mechanisms: Option<Vec<String>>,
    /// Combined mode type (only if mode is "combined")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub combined_mode_type: Option<String>,
    /// Combined threshold (only if mode is "combined" with threshold)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub combined_threshold: Option<u32>,
}

/// Mode-specific settings (sanitized)
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SybilModeSettings {
    None {},
    ProofOfWork {
        difficulty: u32,
    },
    RateLimit {
        interval: String,
        interval_secs: u64,
    },
    Invitation {
        invites_per_user: u32,
        cooldown: String,
        cooldown_secs: u64,
        expires: String,
        expires_secs: u64,
        new_user_wait: String,
        new_user_wait_secs: u64,
        persistence_path: String,
        bootstrap_users_configured: bool,
    },
    ProgressiveTrust {
        levels: Vec<TrustLevelSummary>,
        persistence_path: String,
    },
    ProofOfDiversity {
        min_score: u8,
        persistence_path: String,
    },
    MultiPartyVouching {
        required_vouchers: u32,
        cooldown: String,
        cooldown_secs: u64,
        expires: String,
        expires_secs: u64,
        new_user_wait: String,
        new_user_wait_secs: u64,
        persistence_path: String,
    },
    WebAuthn {
        max_proof_age: Option<String>,
        max_proof_age_secs: Option<i64>,
    },
}

/// Summary of a progressive trust level
#[derive(Debug, Clone, Serialize)]
pub struct TrustLevelSummary {
    pub min_age: String,
    pub min_age_secs: u64,
    pub max_tokens: u32,
    pub cooldown: String,
    pub cooldown_secs: u64,
}

impl SybilConfigSummary {
    /// Create a summary from a SybilConfig
    pub fn from_config(config: &crate::config::SybilConfig) -> Self {
        use freebird_common::duration::format_duration;

        let (mode_description, settings) = match config.mode.as_str() {
            "none" => (
                "No Sybil resistance - anyone can request tokens".to_string(),
                SybilModeSettings::None {},
            ),
            "pow" | "proof_of_work" => (
                format!(
                    "Proof of Work with {} leading zero bits required",
                    config.pow_difficulty
                ),
                SybilModeSettings::ProofOfWork {
                    difficulty: config.pow_difficulty,
                },
            ),
            "rate_limit" => (
                format!(
                    "Rate limiting - one token per {}",
                    format_duration(config.rate_limit_secs)
                ),
                SybilModeSettings::RateLimit {
                    interval: format_duration(config.rate_limit_secs),
                    interval_secs: config.rate_limit_secs,
                },
            ),
            "invitation" => (
                "Invitation-based - users need valid invitation codes".to_string(),
                SybilModeSettings::Invitation {
                    invites_per_user: config.invite_per_user,
                    cooldown: format_duration(config.invite_cooldown_secs),
                    cooldown_secs: config.invite_cooldown_secs,
                    expires: format_duration(config.invite_expires_secs),
                    expires_secs: config.invite_expires_secs,
                    new_user_wait: format_duration(config.invite_new_user_wait_secs),
                    new_user_wait_secs: config.invite_new_user_wait_secs,
                    persistence_path: config.invite_persistence_path.display().to_string(),
                    bootstrap_users_configured: config.bootstrap_users.is_some(),
                },
            ),
            "progressive_trust" => {
                let levels: Vec<TrustLevelSummary> = config
                    .progressive_trust_levels
                    .iter()
                    .filter_map(|s| {
                        let parts: Vec<&str> = s.split(':').collect();
                        if parts.len() >= 3 {
                            let min_age_secs: u64 =
                                freebird_common::duration::parse_duration(parts[0]).ok()?;
                            let max_tokens: u32 = parts[1].parse().ok()?;
                            let cooldown_secs: u64 =
                                freebird_common::duration::parse_duration(parts[2]).ok()?;
                            Some(TrustLevelSummary {
                                min_age: format_duration(min_age_secs),
                                min_age_secs,
                                max_tokens,
                                cooldown: format_duration(cooldown_secs),
                                cooldown_secs,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                (
                    format!("Progressive Trust with {} trust levels", levels.len()),
                    SybilModeSettings::ProgressiveTrust {
                        levels,
                        persistence_path: config
                            .progressive_trust_persistence_path
                            .display()
                            .to_string(),
                    },
                )
            }
            "proof_of_diversity" => (
                format!(
                    "Proof of Diversity - minimum score {} required",
                    config.proof_of_diversity_min_score
                ),
                SybilModeSettings::ProofOfDiversity {
                    min_score: config.proof_of_diversity_min_score,
                    persistence_path: config
                        .proof_of_diversity_persistence_path
                        .display()
                        .to_string(),
                },
            ),
            "multi_party_vouching" => (
                format!(
                    "Multi-Party Vouching - {} vouchers required",
                    config.multi_party_vouching_required_vouchers
                ),
                SybilModeSettings::MultiPartyVouching {
                    required_vouchers: config.multi_party_vouching_required_vouchers,
                    cooldown: format_duration(config.multi_party_vouching_cooldown_secs),
                    cooldown_secs: config.multi_party_vouching_cooldown_secs,
                    expires: format_duration(config.multi_party_vouching_expires_secs),
                    expires_secs: config.multi_party_vouching_expires_secs,
                    new_user_wait: format_duration(config.multi_party_vouching_new_user_wait_secs),
                    new_user_wait_secs: config.multi_party_vouching_new_user_wait_secs,
                    persistence_path: config
                        .multi_party_vouching_persistence_path
                        .display()
                        .to_string(),
                },
            ),
            "webauthn" => (
                "WebAuthn - hardware-backed authentication".to_string(),
                SybilModeSettings::WebAuthn {
                    max_proof_age: config
                        .webauthn_max_proof_age
                        .map(|s| format_duration(s as u64)),
                    max_proof_age_secs: config.webauthn_max_proof_age,
                },
            ),
            "combined" => (
                format!(
                    "Combined mode ({}) with {} mechanisms",
                    config.combined_mode,
                    config.combined_mechanisms.len()
                ),
                SybilModeSettings::None {}, // Settings will be in combined_* fields
            ),
            other => (
                format!("Unknown mode: {}", other),
                SybilModeSettings::None {},
            ),
        };

        let (combined_mechanisms, combined_mode_type, combined_threshold) =
            if config.mode == "combined" {
                (
                    Some(config.combined_mechanisms.clone()),
                    Some(config.combined_mode.clone()),
                    if config.combined_mode == "threshold" {
                        Some(config.combined_threshold)
                    } else {
                        None
                    },
                )
            } else {
                (None, None, None)
            };

        Self {
            mode: config.mode.clone(),
            mode_description,
            settings,
            combined_mechanisms,
            combined_mode_type,
            combined_threshold,
        }
    }
}

/// Response containing current configuration
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub issuer_id: String,
    pub sybil: SybilConfigSummary,
    pub epoch_duration: String,
    pub epoch_duration_secs: u64,
    pub epoch_retention: u32,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub webauthn_enabled: bool,
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

/// Parameters for listing invitations with pagination and filtering
#[derive(Debug, Deserialize)]
pub struct ListInvitationsParams {
    /// Maximum number of invitations to return (default: 50, max: 100)
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Number of invitations to skip for pagination (default: 0)
    #[serde(default)]
    pub offset: usize,
    /// Filter by status: "pending", "redeemed", or "all" (default: all)
    pub status: Option<String>,
    /// Filter by inviter user ID (exact match)
    pub inviter_id: Option<String>,
    /// Filter by minimum creation date (Unix timestamp)
    pub date_from: Option<u64>,
    /// Filter by maximum creation date (Unix timestamp)
    pub date_to: Option<u64>,
}

fn default_limit() -> usize {
    50
}

/// Paginated response for listing invitations
#[derive(Debug, Serialize)]
pub struct ListInvitationsResponse {
    /// The invitations for the current page
    pub invitations: Vec<crate::sybil_resistance::invitation::Invitation>,
    /// Total number of invitations in the system
    pub total: usize,
    /// Current offset (number of items skipped)
    pub offset: usize,
    /// Number of items returned in this response
    pub limit: usize,
    /// Whether there are more items after this page
    pub has_more: bool,
}

/// Response for getting a single invitation by code
#[derive(Debug, Serialize)]
pub struct GetInvitationResponse {
    /// The invitation code
    pub code: String,
    /// User ID who created this invite
    pub inviter_id: String,
    /// User ID who redeemed it (null if not yet redeemed)
    pub invitee_id: Option<String>,
    /// When the invitation was created (Unix timestamp)
    pub created_at: u64,
    /// When the invitation expires (Unix timestamp)
    pub expires_at: u64,
    /// Whether this invitation has been redeemed
    pub redeemed: bool,
}

/// Response after revoking a pending invitation
#[derive(Debug, Serialize)]
pub struct RevokeInvitationResponse {
    pub ok: bool,
    pub code: String,
    pub inviter_id: String,
}

/// Request to add a multi-party voucher
#[derive(Debug, Deserialize)]
pub struct AddVoucherRequest {
    pub user_id: String,
    pub public_key_b64: String,
}

/// Response after adding/removing a voucher
#[derive(Debug, Serialize)]
pub struct VoucherMutationResponse {
    pub ok: bool,
    pub user_id: String,
    pub voucher_id_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ListVouchersResponse {
    pub vouchers: Vec<VoucherSummary>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct ListPendingVouchesResponse {
    pub pending: Vec<PendingVouchSummary>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct SubmitVouchRequest {
    pub voucher_id: String,
    pub vouchee_id: String,
    pub signature_b64: String,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct SubmitVouchResponse {
    pub ok: bool,
    pub vouchee_id_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct VoucheeRequest {
    pub vouchee_id: String,
}

#[derive(Debug, Serialize)]
pub struct ClearPendingVouchesResponse {
    pub ok: bool,
    pub vouchee_id: String,
    pub removed_count: usize,
}

/// Parameters for listing users with pagination
#[derive(Debug, Deserialize)]
pub struct ListUsersParams {
    /// Maximum number of users to return (default: 50, max: 100)
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Number of users to skip for pagination (default: 0)
    #[serde(default)]
    pub offset: usize,
}

/// Paginated response for listing users
#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    /// The users for the current page
    pub users: Vec<UserSummary>,
    /// Total number of users in the system
    pub total: usize,
    /// Current offset (number of items skipped)
    pub offset: usize,
    /// Number of items returned in this response
    pub limit: usize,
    /// Whether there are more items after this page
    pub has_more: bool,
}

/// Parameters for listing audit logs
#[derive(Debug, Deserialize)]
pub struct ListAuditParams {
    /// Maximum number of entries to return (default: 100, max: 500)
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
    /// Number of entries to skip for pagination (default: 0)
    #[serde(default)]
    pub offset: usize,
    /// Filter by log level (optional)
    pub level: Option<String>,
}

fn default_audit_limit() -> usize {
    100
}

/// Paginated response for listing audit logs
#[derive(Debug, Serialize)]
pub struct ListAuditResponse {
    /// The audit entries for the current page
    pub entries: Vec<crate::audit::AuditEntry>,
    /// Total number of entries in the audit log
    pub total: usize,
    /// Current offset (number of entries skipped)
    pub offset: usize,
    /// Number of entries returned in this response
    pub limit: usize,
    /// Whether there are more entries after this page
    pub has_more: bool,
}

// ============================================================================
// Error Types
// ============================================================================

/// Admin API errors
#[derive(Debug)]
pub enum AdminError {
    Unauthorized,
    RateLimited(u64), // seconds until unblock
    UserNotFound(String),
    InvitationNotFound,
    InvalidRequest(String),
    Internal(String),
}

impl AdminError {
    fn status_code(&self) -> StatusCode {
        match self {
            AdminError::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            AdminError::UserNotFound(_) => StatusCode::NOT_FOUND,
            AdminError::InvitationNotFound => StatusCode::NOT_FOUND,
            AdminError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            AdminError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> String {
        match self {
            AdminError::Unauthorized => "unauthorized".to_string(),
            AdminError::RateLimited(secs) => {
                format!("too many failed attempts, try again in {} seconds", secs)
            }
            AdminError::UserNotFound(id) => format!("user not found: {}", id),
            AdminError::InvitationNotFound => "invitation not found".to_string(),
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
// Input Validation
// ============================================================================

/// Maximum allowed length for user IDs
const MAX_USER_ID_LENGTH: usize = 256;

/// Maximum allowed length for key IDs (kid)
const MAX_KID_LENGTH: usize = 128;

/// Validate a user ID input
///
/// Returns an error if the user ID is empty, too long, or contains invalid characters.
/// Valid characters: alphanumeric, hyphens, underscores, colons, periods, and @
fn validate_user_id(user_id: &str) -> Result<(), AdminError> {
    if user_id.is_empty() {
        return Err(AdminError::InvalidRequest(
            "user_id cannot be empty".to_string(),
        ));
    }

    if user_id.len() > MAX_USER_ID_LENGTH {
        return Err(AdminError::InvalidRequest(format!(
            "user_id exceeds maximum length of {} characters",
            MAX_USER_ID_LENGTH
        )));
    }

    // Check for valid characters (alphanumeric, hyphens, underscores, colons, periods, @)
    // This allows common formats like emails, DIDs, and UUIDs
    if !user_id
        .chars()
        .all(|c| c.is_alphanumeric() || "-_:.@".contains(c))
    {
        return Err(AdminError::InvalidRequest(
            "user_id contains invalid characters (allowed: alphanumeric, - _ : . @)".to_string(),
        ));
    }

    // Reject control characters and null bytes
    if user_id.chars().any(|c| c.is_control()) {
        return Err(AdminError::InvalidRequest(
            "user_id cannot contain control characters".to_string(),
        ));
    }

    Ok(())
}

/// Validate a key ID (kid) input
fn validate_kid(kid: &str) -> Result<(), AdminError> {
    if kid.is_empty() {
        return Err(AdminError::InvalidRequest(
            "kid cannot be empty".to_string(),
        ));
    }

    if kid.len() > MAX_KID_LENGTH {
        return Err(AdminError::InvalidRequest(format!(
            "kid exceeds maximum length of {} characters",
            MAX_KID_LENGTH
        )));
    }

    // Similar character restrictions as user_id
    if !kid
        .chars()
        .all(|c| c.is_alphanumeric() || "-_:.".contains(c))
    {
        return Err(AdminError::InvalidRequest(
            "kid contains invalid characters (allowed: alphanumeric, - _ : .)".to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// UI Handler
// ============================================================================

/// Serve the admin UI with security headers
pub async fn admin_ui_handler() -> impl IntoResponse {
    const ADMIN_UI_HTML: &str = include_str!("../admin_ui/index.html");
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-security-policy",
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse().unwrap(),
    );
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("x-xss-protection", "0".parse().unwrap());
    (headers, Html(ADMIN_UI_HTML))
}

// ============================================================================
// Authentication
// ============================================================================

/// Constant-time API key verification using HMAC-then-compare.
///
/// Both values are HMAC'd with a fixed key to produce equal-length digests,
/// eliminating the timing side-channel from length comparison.
fn constant_time_key_verify(expected: &str, provided: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;
    let key = b"freebird-admin-key-compare";

    let mut mac_expected = HmacSha256::new_from_slice(key).unwrap();
    mac_expected.update(expected.as_bytes());
    let h_expected = mac_expected.finalize().into_bytes();

    let mut mac_provided = HmacSha256::new_from_slice(key).unwrap();
    mac_provided.update(provided.as_bytes());
    let h_provided = mac_provided.finalize().into_bytes();

    bool::from(h_expected.ct_eq(&h_provided))
}

/// Extract client IP from headers or connection info
fn extract_client_ip(
    headers: &HeaderMap,
    behind_proxy: bool,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Option<IpAddr> {
    if behind_proxy {
        // Try X-Forwarded-For first (may contain comma-separated list)
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Take the first (leftmost) IP, which is the original client
            if let Some(first_ip) = xff.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        // Fallback to X-Real-IP
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    connect_info.map(|info| info.0.ip())
}

/// Verify authentication via session cookie or X-Admin-Key header with rate limiting
async fn verify_api_key_with_rate_limit(
    headers: &HeaderMap,
    state: &AdminState,
    client_ip: Option<IpAddr>,
) -> Result<(), AdminError> {
    // Check session cookie first (preferred, set by /admin/login)
    if let Some(token) = extract_session_cookie(headers) {
        if verify_session_token(&state.session_key, &token) {
            return Ok(());
        }
    }

    // Fallback to X-Admin-Key header for API/CLI clients
    let Some(ip) = client_ip else {
        warn!("Admin API request without client IP; skipping auth rate-limit");

        let provided_key = headers
            .get("x-admin-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(AdminError::Unauthorized)?;

        if !constant_time_key_verify(&state.api_key, provided_key) {
            warn!("Invalid admin API key provided from unknown IP");
            return Err(AdminError::Unauthorized);
        }

        return Ok(());
    };

    // Check if IP is currently rate-limited
    if let Err(seconds_remaining) = state.rate_limiter.check_allowed(ip).await {
        return Err(AdminError::RateLimited(seconds_remaining));
    }

    let provided_key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AdminError::Unauthorized)?;

    if !constant_time_key_verify(&state.api_key, provided_key) {
        state.rate_limiter.record_failure(ip).await;
        warn!("Invalid admin API key provided from IP: {}", ip);
        return Err(AdminError::Unauthorized);
    }

    state.rate_limiter.record_success(ip).await;
    Ok(())
}

// ============================================================================
// Login / Logout Handlers
// ============================================================================

#[derive(Deserialize)]
struct LoginRequest {
    api_key: String,
}

/// POST /admin/login — verify API key and set HttpOnly session cookie
async fn login_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);

    // Rate-limit login attempts by IP
    if let Some(ip) = client_ip {
        if let Err(seconds_remaining) = state.rate_limiter.check_allowed(ip).await {
            return Err(AdminError::RateLimited(seconds_remaining));
        }
    }

    if !constant_time_key_verify(&state.api_key, &req.api_key) {
        if let Some(ip) = client_ip {
            state.rate_limiter.record_failure(ip).await;
        }
        warn!("Failed login attempt from {:?}", client_ip);
        return Err(AdminError::Unauthorized);
    }

    if let Some(ip) = client_ip {
        state.rate_limiter.record_success(ip).await;
    }

    let token = compute_session_token(&state.session_key);
    let secure_flag = if state.require_tls { "; Secure" } else { "" };
    let cookie = format!(
        "freebird_session={}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=86400{}",
        token, secure_flag
    );

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("set-cookie", cookie.parse().unwrap());

    Ok((resp_headers, Json(serde_json::json!({"status": "ok"}))))
}

/// POST /admin/logout — clear session cookie
async fn logout_handler() -> impl IntoResponse {
    let cookie = "freebird_session=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0";
    let mut headers = HeaderMap::new();
    headers.insert("set-cookie", cookie.parse().unwrap());
    (headers, Json(serde_json::json!({"status": "ok"})))
}

// ============================================================================
// Invitation System Handlers
// ============================================================================

pub async fn health_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<HealthResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    Ok(Json(HealthResponse {
        service: "issuer".to_string(),
        status: "ok".to_string(),
        uptime_seconds: 0,
        invitation_system_status: "operational".to_string(),
    }))
}

pub async fn get_stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<StatsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

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

/// Get current configuration (sanitized - no secrets)
pub async fn get_config_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ConfigResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let summary = &state.config_summary;

    info!("Admin: retrieved configuration summary");

    Ok(Json(ConfigResponse {
        issuer_id: summary.issuer_id.clone(),
        sybil: summary.sybil_config.clone(),
        epoch_duration: freebird_common::duration::format_duration(summary.epoch_duration_secs),
        epoch_duration_secs: summary.epoch_duration_secs,
        epoch_retention: summary.epoch_retention,
        require_tls: summary.require_tls,
        behind_proxy: summary.behind_proxy,
        webauthn_enabled: summary.webauthn_enabled,
    }))
}

/// Prometheus metrics endpoint
/// Returns metrics in Prometheus text exposition format
pub async fn metrics_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<String, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let stats = state.invitation_system.get_stats().await;
    let key_stats = state.multi_key_voprf.key_stats().await;

    let mut output = String::new();

    macro_rules! metric {
        ($name:expr, $type:expr, $help:expr, $value:expr) => {
            output.push_str(&format!(
                "# HELP {} {}\n# TYPE {} {}\n{} {}\n",
                $name, $help, $name, $type, $name, $value
            ));
        };
    }

    // User metrics
    metric!(
        "freebird_users_total",
        "gauge",
        "Total number of registered users",
        stats.total_users
    );
    metric!(
        "freebird_users_banned",
        "gauge",
        "Number of banned users",
        stats.banned_users
    );

    // Invitation metrics
    metric!(
        "freebird_invitations_total",
        "counter",
        "Total invitations created",
        stats.total_invitations
    );
    metric!(
        "freebird_invitations_redeemed",
        "counter",
        "Total invitations redeemed",
        stats.redeemed_invitations
    );
    metric!(
        "freebird_invitations_pending",
        "gauge",
        "Pending invitations",
        stats.pending_invitations
    );

    // Key metrics (use pre-computed stats)
    metric!(
        "freebird_keys_total",
        "gauge",
        "Total number of signing keys",
        key_stats.total_keys
    );
    metric!(
        "freebird_keys_active",
        "gauge",
        "Number of active signing keys",
        key_stats.active_keys
    );
    metric!(
        "freebird_keys_deprecated",
        "gauge",
        "Number of deprecated signing keys",
        key_stats.deprecated_keys
    );
    metric!(
        "freebird_keys_expiring_soon",
        "gauge",
        "Number of keys expiring within 7 days",
        key_stats.expiring_soon
    );

    // Sybil mode info (as a label)
    output.push_str(&format!(
        "# HELP freebird_info Freebird instance information\n# TYPE freebird_info gauge\nfreebird_info{{sybil_mode=\"{}\"}} 1\n",
        state.config_summary.sybil_config.mode
    ));

    // Append Prometheus histogram/counter metrics from the shared registry
    output.push_str(&freebird_common::metrics::encode_metrics());

    info!("Admin: retrieved Prometheus metrics");

    Ok(output)
}

pub async fn grant_invites_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<GrantInvitesRequest>,
) -> Result<Json<GrantInvitesResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate inputs
    validate_user_id(&req.user_id)?;

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

    // Audit log
    state
        .audit_log
        .log(
            AuditEntry::success("invites_granted")
                .with_user(&req.user_id)
                .with_details(format!("Granted {} invite(s)", req.count)),
        )
        .await;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<BanUserRequest>,
) -> Result<Json<BanUserResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate inputs
    validate_user_id(&req.user_id)?;

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

    // Audit log
    state
        .audit_log
        .log(
            AuditEntry::warning("user_banned")
                .with_user(&req.user_id)
                .with_details(format!(
                    "Banned {} user(s){}",
                    banned_count,
                    if req.ban_tree { " (tree ban)" } else { "" }
                )),
        )
        .await;

    Ok(Json(BanUserResponse {
        ok: true,
        user_id: req.user_id,
        banned_count,
    }))
}

pub async fn unban_user_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<UnbanUserRequest>,
) -> Result<Json<UnbanUserResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&req.user_id)?;

    state
        .invitation_system
        .unban_user(&req.user_id)
        .await
        .map_err(|e| {
            let err_msg = e.to_string();
            if err_msg.contains("not found") {
                AdminError::UserNotFound(req.user_id.clone())
            } else {
                AdminError::Internal(err_msg)
            }
        })?;

    info!(user_id = %req.user_id, "Admin: unbanned user");
    state
        .audit_log
        .log(AuditEntry::success("user_unbanned").with_user(&req.user_id))
        .await;

    Ok(Json(UnbanUserResponse {
        ok: true,
        user_id: req.user_id,
    }))
}

pub async fn add_bootstrap_user_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<AddBootstrapUserRequest>,
) -> Result<Json<AddBootstrapUserResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate inputs
    validate_user_id(&req.user_id)?;

    state
        .invitation_system
        .add_bootstrap_user(req.user_id.clone(), req.invite_count)
        .await;

    info!(
        user_id = %req.user_id,
        invite_count = req.invite_count,
        "Admin: added bootstrap user"
    );

    // Audit log
    state
        .audit_log
        .log(
            AuditEntry::success("bootstrap_user_added")
                .with_user(&req.user_id)
                .with_details(format!("Granted {} invites", req.invite_count)),
        )
        .await;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<RegisterOwnerRequest>,
) -> Result<Json<RegisterOwnerResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate inputs
    validate_user_id(&req.user_id)?;

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

    // Audit log
    state
        .audit_log
        .log(
            AuditEntry::success("owner_registered")
                .with_user(&req.user_id)
                .with_details("Instance owner registered"),
        )
        .await;

    Ok(Json(RegisterOwnerResponse {
        success: true,
        owner: req.user_id,
    }))
}

pub async fn create_invitations_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<CreateInvitationsRequest>,
) -> Result<Json<CreateInvitationsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate inputs
    validate_user_id(&req.inviter_id)?;

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
        match state
            .invitation_system
            .generate_invite_admin(&req.inviter_id)
            .await
        {
            Ok((code, signature, expires_at)) => {
                invitations.push(InvitationCode {
                    code,
                    signature: base64ct::Base64UrlUnpadded::encode_string(&signature),
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

    // Audit log
    state
        .audit_log
        .log(
            AuditEntry::success("invitations_created")
                .with_user(&req.inviter_id)
                .with_details(format!("Created {} invitation(s)", req.count)),
        )
        .await;

    Ok(Json(CreateInvitationsResponse {
        ok: true,
        inviter_id: req.inviter_id,
        invitations,
    }))
}

pub async fn save_state_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Query(params): Query<ListUsersParams>,
) -> Result<Json<ListUsersResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Clamp limit to reasonable bounds (1-100)
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset;

    // Get total count for pagination info
    let total = state.invitation_system.count_users().await;

    // Get paginated users
    let users = state.invitation_system.list_users(limit, offset).await;
    let summaries: Vec<UserSummary> = users
        .into_iter()
        .map(|(user_id, invites_remaining, banned)| UserSummary {
            user_id,
            invites_remaining,
            banned,
        })
        .collect();
    let returned_count = summaries.len();

    // Calculate if there are more items
    let has_more = offset + returned_count < total;

    info!(
        "Admin: listed users (offset={}, limit={}, returned={}, total={})",
        offset, limit, returned_count, total
    );

    Ok(Json(ListUsersResponse {
        users: summaries,
        total,
        offset,
        limit,
        has_more,
    }))
}

pub async fn get_user_details_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(user_id): Path<String>,
) -> Result<Json<UserDetailsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate path parameter
    validate_user_id(&user_id)?;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Query(params): Query<ListInvitationsParams>,
) -> Result<Json<ListInvitationsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Clamp limit to reasonable bounds (1-100)
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset;

    // Build filter from params
    let filter = if params.status.is_some()
        || params.inviter_id.is_some()
        || params.date_from.is_some()
        || params.date_to.is_some()
    {
        let redeemed = match params.status.as_deref() {
            Some("redeemed") => Some(true),
            Some("pending") => Some(false),
            _ => None, // "all" or no filter
        };
        Some(InvitationFilter {
            redeemed,
            inviter_id: params.inviter_id.clone(),
            date_from: params.date_from,
            date_to: params.date_to,
        })
    } else {
        None
    };

    // Get total count for pagination info (with filter)
    let total = state
        .invitation_system
        .count_invitations_filtered(filter.clone())
        .await;

    // Get paginated invitations with filter
    let invitations = state
        .invitation_system
        .list_invitations_filtered(limit, offset, filter)
        .await;
    let returned_count = invitations.len();

    // Calculate if there are more items
    let has_more = offset + returned_count < total;

    info!(
        "Admin: listed invitations (offset={}, limit={}, returned={}, total={})",
        offset, limit, returned_count, total
    );

    Ok(Json(ListInvitationsResponse {
        invitations,
        total,
        offset,
        limit,
        has_more,
    }))
}

/// Get a single invitation by its code
///
/// This endpoint allows looking up an invitation's details by its code,
/// which is useful for finding the invitee_id associated with a redeemed invitation.
pub async fn get_invitation_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(code): Path<String>,
) -> Result<Json<GetInvitationResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let invitation = state
        .invitation_system
        .get_invitation_details(&code)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                AdminError::InvitationNotFound
            } else {
                AdminError::Internal(msg)
            }
        })?;

    info!(code = %code, "Admin: retrieved invitation details");

    Ok(Json(GetInvitationResponse {
        code: invitation.code().to_string(),
        inviter_id: invitation.inviter_id().to_string(),
        invitee_id: invitation.invitee_id().map(|s| s.to_string()),
        created_at: invitation.created_at(),
        expires_at: invitation.expires_at(),
        redeemed: invitation.redeemed(),
    }))
}

pub async fn revoke_invitation_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(code): Path<String>,
) -> Result<Json<RevokeInvitationResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let invitation = state
        .invitation_system
        .revoke_invitation(&code)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                AdminError::InvitationNotFound
            } else if msg.contains("redeemed") {
                AdminError::InvalidRequest(msg)
            } else {
                AdminError::Internal(msg)
            }
        })?;

    info!(code = %code, "Admin: revoked invitation");
    state
        .audit_log
        .log(
            AuditEntry::warning("invitation_revoked")
                .with_user(invitation.inviter_id())
                .with_details(format!("Revoked invitation {}", code)),
        )
        .await;

    Ok(Json(RevokeInvitationResponse {
        ok: true,
        code,
        inviter_id: invitation.inviter_id().to_string(),
    }))
}

// ============================================================================
// Audit Log Handlers
// ============================================================================

pub async fn list_audit_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Query(params): Query<ListAuditParams>,
) -> Result<Json<ListAuditResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Clamp limit to reasonable bounds (1-500)
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset;

    // Get total count for pagination info
    let total = state.audit_log.count().await;

    // Get entries (optionally filtered by level)
    let entries = if let Some(ref level) = params.level {
        state
            .audit_log
            .get_entries_by_level(level, limit, offset)
            .await
    } else {
        state.audit_log.get_entries(limit, offset).await
    };
    let returned_count = entries.len();

    // Calculate if there are more items
    let has_more = offset + returned_count < total;

    info!(
        "Admin: listed audit entries (offset={}, limit={}, returned={}, total={})",
        offset, limit, returned_count, total
    );

    Ok(Json(ListAuditResponse {
        entries,
        total,
        offset,
        limit,
        has_more,
    }))
}

// ============================================================================
// Key Management Handlers
// ============================================================================

pub async fn list_keys_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ListKeysResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let keys = state.multi_key_voprf.list_keys().await;
    let stats = state.multi_key_voprf.key_stats().await;

    info!("Admin: listed keys (count={})", keys.len());

    Ok(Json(ListKeysResponse { keys, stats }))
}

pub async fn rotate_key_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<RotateKeyResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate inputs
    validate_kid(&req.new_kid)?;

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

    // Audit log
    state
        .audit_log
        .log(AuditEntry::info("key_rotated").with_details(format!(
            "Rotated from {} to {}, grace period {} seconds",
            old_kid, req.new_kid, grace_period
        )))
        .await;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<CleanupKeysResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(kid): Path<String>,
) -> Result<Json<ForceRemoveKeyResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Validate path parameter
    validate_kid(&kid)?;

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
// Multi-Party Vouching Handlers
// ============================================================================

fn require_vouching_system(
    state: &AdminState,
) -> Result<Arc<MultiPartyVouchingSystem>, AdminError> {
    state.multi_party_vouching.clone().ok_or_else(|| {
        AdminError::InvalidRequest("multi-party vouching is not configured".to_string())
    })
}

pub async fn list_vouchers_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ListVouchersResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    let system = require_vouching_system(&state)?;

    let vouchers = system.list_vouchers().await;
    let total = vouchers.len();
    Ok(Json(ListVouchersResponse { vouchers, total }))
}

pub async fn add_voucher_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<AddVoucherRequest>,
) -> Result<Json<VoucherMutationResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&req.user_id)?;
    let system = require_vouching_system(&state)?;

    let public_key_bytes = base64ct::Base64UrlUnpadded::decode_vec(&req.public_key_b64)
        .map_err(|_| AdminError::InvalidRequest("invalid public_key_b64".to_string()))?;
    let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|_| AdminError::InvalidRequest("invalid voucher public key".to_string()))?;

    system
        .add_voucher(req.user_id.clone(), public_key)
        .await
        .map_err(|e| AdminError::Internal(e.to_string()))?;
    let voucher_id_hash = system.hash_user_id(&req.user_id);

    info!(user_id = %req.user_id, "Admin: added voucher");
    state
        .audit_log
        .log(AuditEntry::success("voucher_added").with_user(&req.user_id))
        .await;

    Ok(Json(VoucherMutationResponse {
        ok: true,
        user_id: req.user_id,
        voucher_id_hash,
    }))
}

pub async fn remove_voucher_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(user_id): Path<String>,
) -> Result<Json<VoucherMutationResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&user_id)?;
    let system = require_vouching_system(&state)?;

    let voucher_id_hash = system.hash_user_id(&user_id);
    system.remove_voucher(&user_id).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") || msg.contains("Voucher") {
            AdminError::UserNotFound(user_id.clone())
        } else {
            AdminError::Internal(msg)
        }
    })?;

    warn!(user_id = %user_id, "Admin: removed voucher");
    state
        .audit_log
        .log(AuditEntry::warning("voucher_removed").with_user(&user_id))
        .await;

    Ok(Json(VoucherMutationResponse {
        ok: true,
        user_id,
        voucher_id_hash,
    }))
}

pub async fn submit_vouch_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<SubmitVouchRequest>,
) -> Result<Json<SubmitVouchResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&req.voucher_id)?;
    validate_user_id(&req.vouchee_id)?;
    let system = require_vouching_system(&state)?;

    let signature_bytes = base64ct::Base64UrlUnpadded::decode_vec(&req.signature_b64)
        .map_err(|_| AdminError::InvalidRequest("invalid signature_b64".to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AdminError::InvalidRequest("invalid ECDSA signature".to_string()))?;

    let proof = system
        .submit_vouch(&req.voucher_id, &req.vouchee_id, signature, req.timestamp)
        .await
        .map_err(|e| AdminError::InvalidRequest(e.to_string()))?;

    info!(voucher_id = %req.voucher_id, vouchee_id = %req.vouchee_id, "Admin: submitted vouch");
    state
        .audit_log
        .log(
            AuditEntry::success("vouch_submitted")
                .with_user(&req.voucher_id)
                .with_details(format!("Vouched for {}", req.vouchee_id)),
        )
        .await;

    Ok(Json(SubmitVouchResponse {
        ok: true,
        vouchee_id_hash: proof.vouchee_id,
    }))
}

pub async fn list_pending_vouches_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ListPendingVouchesResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    let system = require_vouching_system(&state)?;

    let pending = system.list_pending_vouches().await;
    let total = pending.len();
    Ok(Json(ListPendingVouchesResponse { pending, total }))
}

pub async fn clear_pending_vouches_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<VoucheeRequest>,
) -> Result<Json<ClearPendingVouchesResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&req.vouchee_id)?;
    let system = require_vouching_system(&state)?;

    let removed_count = system
        .clear_pending_vouches(&req.vouchee_id)
        .await
        .map_err(|e| AdminError::InvalidRequest(e.to_string()))?;
    state
        .audit_log
        .log(
            AuditEntry::warning("pending_vouches_cleared")
                .with_user(&req.vouchee_id)
                .with_details(format!("Removed {} pending vouch(es)", removed_count)),
        )
        .await;

    Ok(Json(ClearPendingVouchesResponse {
        ok: true,
        vouchee_id: req.vouchee_id,
        removed_count,
    }))
}

pub async fn mark_vouching_successful_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<VoucheeRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&req.vouchee_id)?;
    let system = require_vouching_system(&state)?;
    system
        .mark_successful(&req.vouchee_id)
        .await
        .map_err(|e| AdminError::InvalidRequest(e.to_string()))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn mark_vouching_problematic_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<VoucheeRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    validate_user_id(&req.vouchee_id)?;
    let system = require_vouching_system(&state)?;
    system
        .mark_problematic(&req.vouchee_id)
        .await
        .map_err(|e| AdminError::InvalidRequest(e.to_string()))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ============================================================================
// Export Handlers
// ============================================================================

/// Export format query parameter
#[derive(Debug, Deserialize)]
pub struct ExportParams {
    /// Export format: "json" (default) or "csv"
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "json".to_string()
}

/// User export record for CSV/JSON
#[derive(Debug, Serialize)]
pub struct UserExport {
    pub user_id: String,
    pub invites_remaining: u32,
    pub banned: bool,
    pub joined_at: u64,
    pub reputation: f64,
}

/// Invitation export record for CSV/JSON
#[derive(Debug, Serialize)]
pub struct InvitationExport {
    pub code: String,
    pub inviter_id: String,
    pub invitee_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub redeemed: bool,
}

/// Audit log export record for CSV/JSON
#[derive(Debug, Serialize)]
pub struct AuditExport {
    pub timestamp: u64,
    pub level: String,
    pub action: String,
    pub user_id: Option<String>,
    pub details: Option<String>,
    pub admin_id: Option<String>,
}

/// Export invitations as JSON or CSV
pub async fn export_invitations_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Query(params): Query<ExportParams>,
) -> Result<impl IntoResponse, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let invitations = state.invitation_system.get_all_invitations().await;
    let exports: Vec<InvitationExport> = invitations
        .iter()
        .map(|inv| InvitationExport {
            code: inv.code().to_string(),
            inviter_id: inv.inviter_id().to_string(),
            invitee_id: inv.invitee_id().map(|s| s.to_string()),
            created_at: inv.created_at(),
            expires_at: inv.expires_at(),
            redeemed: inv.redeemed(),
        })
        .collect();

    info!(
        "Admin: exported {} invitations as {}",
        exports.len(),
        params.format
    );

    if params.format == "csv" {
        let mut csv = String::from("code,inviter_id,invitee_id,created_at,expires_at,redeemed\n");
        for inv in &exports {
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                inv.code,
                inv.inviter_id,
                inv.invitee_id.as_deref().unwrap_or(""),
                inv.created_at,
                inv.expires_at,
                inv.redeemed
            ));
        }
        Ok((
            [
                (axum::http::header::CONTENT_TYPE, "text/csv"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"invitations.csv\"",
                ),
            ],
            csv,
        )
            .into_response())
    } else {
        Ok(Json(exports).into_response())
    }
}

/// Export users as JSON or CSV
pub async fn export_users_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Query(params): Query<ExportParams>,
) -> Result<impl IntoResponse, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let users = state.invitation_system.get_all_users().await;
    let exports: Vec<UserExport> = users
        .into_iter()
        .map(
            |(user_id, invites_remaining, banned, joined_at, reputation)| UserExport {
                user_id,
                invites_remaining,
                banned,
                joined_at,
                reputation,
            },
        )
        .collect();

    info!(
        "Admin: exported {} users as {}",
        exports.len(),
        params.format
    );

    if params.format == "csv" {
        let mut csv = String::from("user_id,invites_remaining,banned,joined_at,reputation\n");
        for user in &exports {
            csv.push_str(&format!(
                "{},{},{},{},{:.2}\n",
                user.user_id, user.invites_remaining, user.banned, user.joined_at, user.reputation
            ));
        }
        Ok((
            [
                (axum::http::header::CONTENT_TYPE, "text/csv"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"users.csv\"",
                ),
            ],
            csv,
        )
            .into_response())
    } else {
        Ok(Json(exports).into_response())
    }
}

/// Export audit logs as JSON or CSV
pub async fn export_audit_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Query(params): Query<ExportParams>,
) -> Result<impl IntoResponse, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    // Get all audit entries (no pagination for export)
    let entries = state.audit_log.get_entries(100000, 0).await;
    let exports: Vec<AuditExport> = entries
        .into_iter()
        .map(|entry| AuditExport {
            timestamp: entry.timestamp,
            level: entry.level,
            action: entry.action,
            user_id: entry.user_id,
            details: entry.details,
            admin_id: entry.admin_id,
        })
        .collect();

    info!(
        "Admin: exported {} audit entries as {}",
        exports.len(),
        params.format
    );

    if params.format == "csv" {
        let mut csv = String::from("timestamp,level,action,user_id,details,admin_id\n");
        for entry in &exports {
            // Escape commas and quotes in text fields
            let details = entry.details.as_deref().unwrap_or("").replace("\"", "\"\"");
            csv.push_str(&format!(
                "{},{},{},{},\"{}\",{}\n",
                entry.timestamp,
                entry.level,
                entry.action,
                entry.user_id.as_deref().unwrap_or(""),
                details,
                entry.admin_id.as_deref().unwrap_or("")
            ));
        }
        Ok((
            [
                (axum::http::header::CONTENT_TYPE, "text/csv"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"audit_log.csv\"",
                ),
            ],
            csv,
        )
            .into_response())
    } else {
        Ok(Json(exports).into_response())
    }
}

// ============================================================================
// WebAuthn Admin Handlers
// ============================================================================

/// WebAuthn credential summary for admin listing
#[derive(Debug, Serialize)]
pub struct WebAuthnCredentialSummary {
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// User ID hash (hashed for privacy)
    pub user_id_hash: String,
    /// Registration timestamp (Unix seconds)
    pub registered_at: i64,
    /// Last used timestamp (Unix seconds, if ever used)
    pub last_used_at: Option<i64>,
}

/// Response for listing WebAuthn credentials
#[derive(Debug, Serialize)]
pub struct ListWebAuthnCredentialsResponse {
    /// List of credentials
    pub credentials: Vec<WebAuthnCredentialSummary>,
    /// Total count
    pub total: usize,
}

/// Response for deleting a WebAuthn credential
#[derive(Debug, Serialize)]
pub struct DeleteWebAuthnCredentialResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct WebAuthnPolicyResponse {
    pub enabled: bool,
    pub attestation_required: bool,
    pub policy: String,
    pub allowed_aaguids: Vec<String>,
    pub audit_logging: bool,
    pub max_credentials_per_user: usize,
    pub require_resident_key: bool,
    pub allow_credential_revocation: bool,
}

/// List all WebAuthn credentials (admin only)
#[cfg(feature = "human-gate-webauthn")]
pub async fn list_webauthn_credentials_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ListWebAuthnCredentialsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let store = state
        .webauthn_store
        .as_ref()
        .ok_or_else(|| AdminError::Internal("WebAuthn not configured".to_string()))?;

    let credentials = store
        .list_all()
        .await
        .map_err(|e| AdminError::Internal(format!("Failed to list credentials: {}", e)))?;

    let summaries: Vec<WebAuthnCredentialSummary> = credentials
        .iter()
        .map(|cred| WebAuthnCredentialSummary {
            credential_id: base64ct::Base64UrlUnpadded::encode_string(&cred.cred_id),
            user_id_hash: cred.user_id_hash.clone(),
            registered_at: cred.registered_at,
            last_used_at: cred.last_used_at,
        })
        .collect();

    let total = summaries.len();

    info!("Admin: listed {} WebAuthn credentials", total);

    Ok(Json(ListWebAuthnCredentialsResponse {
        credentials: summaries,
        total,
    }))
}

/// Delete a WebAuthn credential by ID (admin only)
#[cfg(feature = "human-gate-webauthn")]
pub async fn delete_webauthn_credential_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(cred_id_b64): Path<String>,
) -> Result<Json<DeleteWebAuthnCredentialResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let store = state
        .webauthn_store
        .as_ref()
        .ok_or_else(|| AdminError::Internal("WebAuthn not configured".to_string()))?;

    // Decode the credential ID from base64url
    let cred_id = base64ct::Base64UrlUnpadded::decode_vec(&cred_id_b64)
        .map_err(|e| AdminError::Internal(format!("Invalid credential ID format: {}", e)))?;

    let deleted = store
        .delete(&cred_id)
        .await
        .map_err(|e| AdminError::Internal(format!("Failed to delete credential: {}", e)))?;

    if deleted {
        info!("Admin: deleted WebAuthn credential {}", cred_id_b64);
        Ok(Json(DeleteWebAuthnCredentialResponse {
            ok: true,
            message: format!("Credential {} deleted successfully", cred_id_b64),
        }))
    } else {
        Err(AdminError::UserNotFound(format!(
            "Credential {} not found",
            cred_id_b64
        )))
    }
}

/// Get WebAuthn stats (admin only)
#[cfg(feature = "human-gate-webauthn")]
pub async fn webauthn_stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;

    let store = state
        .webauthn_store
        .as_ref()
        .ok_or_else(|| AdminError::Internal("WebAuthn not configured".to_string()))?;

    let count = store
        .count_credentials()
        .await
        .map_err(|e| AdminError::Internal(format!("Failed to count credentials: {}", e)))?;

    Ok(Json(serde_json::json!({
        "total_credentials": count,
        "enabled": true
    })))
}

#[cfg(feature = "human-gate-webauthn")]
pub async fn webauthn_policy_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<WebAuthnPolicyResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    let config = crate::webauthn::AttestationConfig::global();
    let mut allowed_aaguids: Vec<String> = config.allowed_aaguids.iter().cloned().collect();
    allowed_aaguids.sort();
    let attestation_required = std::env::var("WEBAUTHN_REQUIRE_ATTESTATION")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Ok(Json(WebAuthnPolicyResponse {
        enabled: state.webauthn_store.is_some(),
        attestation_required,
        policy: config.policy.to_string_value().to_string(),
        allowed_aaguids,
        audit_logging: config.audit_logging,
        max_credentials_per_user: config.max_credentials_per_user,
        require_resident_key: config.require_resident_key,
        allow_credential_revocation: config.allow_credential_revocation,
    }))
}

// Fallback handlers when WebAuthn is not enabled
#[cfg(not(feature = "human-gate-webauthn"))]
pub async fn list_webauthn_credentials_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ListWebAuthnCredentialsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    Ok(Json(ListWebAuthnCredentialsResponse {
        credentials: vec![],
        total: 0,
    }))
}

#[cfg(not(feature = "human-gate-webauthn"))]
pub async fn delete_webauthn_credential_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(_cred_id_b64): Path<String>,
) -> Result<Json<DeleteWebAuthnCredentialResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    Err(AdminError::Internal(
        "WebAuthn feature not enabled".to_string(),
    ))
}

#[cfg(not(feature = "human-gate-webauthn"))]
pub async fn webauthn_stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    Ok(Json(serde_json::json!({
        "total_credentials": 0,
        "enabled": false
    })))
}

#[cfg(not(feature = "human-gate-webauthn"))]
pub async fn webauthn_policy_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<WebAuthnPolicyResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info);
    verify_api_key_with_rate_limit(&headers, &state, client_ip).await?;
    Ok(Json(WebAuthnPolicyResponse {
        enabled: false,
        attestation_required: false,
        policy: "disabled".to_string(),
        allowed_aaguids: vec![],
        audit_logging: false,
        max_credentials_per_user: 0,
        require_resident_key: false,
        allow_credential_revocation: false,
    }))
}

// ============================================================================
// Router Configuration
// ============================================================================

#[cfg(feature = "human-gate-webauthn")]
#[allow(clippy::too_many_arguments)]
pub fn admin_router(
    invitation_system: Arc<InvitationSystem>,
    multi_party_vouching: Option<Arc<MultiPartyVouchingSystem>>,
    multi_key_voprf: Arc<MultiKeyVoprfCore>,
    audit_log: Arc<AuditLog>,
    api_key: String,
    behind_proxy: bool,
    require_tls: bool,
    webauthn_store: Option<crate::webauthn::CredentialStore>,
    config_summary: ConfigSummary,
) -> axum::Router {
    let session_key = derive_session_key(&api_key);
    let state = Arc::new(AdminState {
        invitation_system,
        multi_party_vouching,
        multi_key_voprf,
        audit_log,
        api_key,
        session_key,
        rate_limiter: AdminRateLimiter::new(),
        behind_proxy,
        require_tls,
        webauthn_store,
        config_summary,
    });

    build_admin_router(state)
}

#[cfg(not(feature = "human-gate-webauthn"))]
#[allow(clippy::too_many_arguments)]
pub fn admin_router(
    invitation_system: Arc<InvitationSystem>,
    multi_party_vouching: Option<Arc<MultiPartyVouchingSystem>>,
    multi_key_voprf: Arc<MultiKeyVoprfCore>,
    audit_log: Arc<AuditLog>,
    api_key: String,
    behind_proxy: bool,
    require_tls: bool,
    config_summary: ConfigSummary,
) -> axum::Router {
    let session_key = derive_session_key(&api_key);
    let state = Arc::new(AdminState {
        invitation_system,
        multi_party_vouching,
        multi_key_voprf,
        audit_log,
        api_key,
        session_key,
        rate_limiter: AdminRateLimiter::new(),
        behind_proxy,
        require_tls,
        config_summary,
    });

    build_admin_router(state)
}

fn build_admin_router(state: Arc<AdminState>) -> axum::Router {
    axum::Router::new()
        .route("/", axum::routing::get(admin_ui_handler))
        .route("/login", axum::routing::post(login_handler))
        .route("/logout", axum::routing::post(logout_handler))
        .route("/health", axum::routing::get(health_handler))
        .route("/stats", axum::routing::get(get_stats_handler))
        .route("/config", axum::routing::get(get_config_handler))
        .route("/metrics", axum::routing::get(metrics_handler))
        .route("/users", axum::routing::get(list_users_handler))
        .route(
            "/users/:user_id",
            axum::routing::get(get_user_details_handler),
        )
        .route("/invites/grant", axum::routing::post(grant_invites_handler))
        .route("/invitations", axum::routing::get(list_invitations_handler))
        .route(
            "/invitations/create",
            axum::routing::post(create_invitations_handler),
        )
        .route(
            "/invitations/:code",
            axum::routing::get(get_invitation_handler).delete(revoke_invitation_handler),
        )
        .route("/users/ban", axum::routing::post(ban_user_handler))
        .route("/users/unban", axum::routing::post(unban_user_handler))
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
        // Multi-party vouching admin routes
        .route(
            "/vouching/vouchers",
            axum::routing::get(list_vouchers_handler).post(add_voucher_handler),
        )
        .route(
            "/vouching/vouchers/:user_id",
            axum::routing::delete(remove_voucher_handler),
        )
        .route(
            "/vouching/vouches",
            axum::routing::post(submit_vouch_handler),
        )
        .route(
            "/vouching/pending",
            axum::routing::get(list_pending_vouches_handler).delete(clear_pending_vouches_handler),
        )
        .route(
            "/vouching/mark-successful",
            axum::routing::post(mark_vouching_successful_handler),
        )
        .route(
            "/vouching/mark-problematic",
            axum::routing::post(mark_vouching_problematic_handler),
        )
        // Audit log route
        .route("/audit", axum::routing::get(list_audit_handler))
        // Export routes
        .route(
            "/export/invitations",
            axum::routing::get(export_invitations_handler),
        )
        .route("/export/users", axum::routing::get(export_users_handler))
        .route("/export/audit", axum::routing::get(export_audit_handler))
        // WebAuthn admin routes
        .route(
            "/webauthn/credentials",
            axum::routing::get(list_webauthn_credentials_handler),
        )
        .route(
            "/webauthn/credentials/:cred_id",
            axum::routing::delete(delete_webauthn_credential_handler),
        )
        .route(
            "/webauthn/stats",
            axum::routing::get(webauthn_stats_handler),
        )
        .route(
            "/webauthn/policy",
            axum::routing::get(webauthn_policy_handler),
        )
        .with_state(state)
}
