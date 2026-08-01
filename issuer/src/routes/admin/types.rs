// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Public request and response types for the issuer admin API.

use crate::multi_key_voprf::{KeyInfo, KeyStats};
use crate::sybil_resistance::invitation::InvitationStats;
use crate::sybil_resistance::multi_party_vouching::{PendingVouchSummary, VoucherSummary};
use serde::{Deserialize, Serialize};

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
    pub allow_unsafe_v4_rotation: bool,
}

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
    pub allow_unsafe_v4_rotation: bool,
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
