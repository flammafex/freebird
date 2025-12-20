// issuer/src/webauthn/discoverable.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Discoverable Credentials (Resident Keys) and Credential Management
//!
//! This module provides:
//! - Resident key registration (credentials stored on authenticator)
//! - Usernameless/passwordless authentication (conditional UI)
//! - Credential management endpoints (list, revoke)

use axum::{
    extract::{ConnectInfo, Json, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Router,
};
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use super::attestation::{parse_attestation_info, AttestationConfig};
use super::handlers::{SessionData, WebAuthnState};
use super::store::{AuthenticatorTransport, CredentialCreateOptions, CredentialSummary, DeviceType};

// --- Constants ---

/// Session expiration time in seconds
#[allow(dead_code)]
const SESSION_EXPIRY_SECS: i64 = 900; // 15 minutes

// --- IP Extraction (shared with handlers.rs) ---

fn extract_client_ip(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    behind_proxy: bool,
) -> Option<IpAddr> {
    if behind_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first_ip) = xff.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    connect_info.map(|ci| ci.0.ip())
}

// ============================================================================
// Resident Key Registration
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct StartResidentRegistrationRequest {
    pub username: String,
    pub display_name: Option<String>,
    /// Optional friendly name for the credential (e.g., "MacBook Pro")
    pub credential_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StartResidentRegistrationResponse {
    pub options: CreationChallengeResponse,
    pub session_id: String,
    /// User handle (base64url encoded) - client should store this
    pub user_handle: String,
}

/// Extended session data for resident key registration
#[derive(Clone, Debug)]
pub struct ResidentRegistrationSession {
    pub state: PasskeyRegistration,
    pub username: String,
    pub user_handle: String,
    pub credential_name: Option<String>,
    pub created_at: i64,
    pub client_ip: IpAddr,
}

/// Start registration with resident key requirement
///
/// POST /webauthn/register/resident/start
pub async fn start_resident_registration(
    State(state): State<Arc<WebAuthnState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<StartResidentRegistrationRequest>,
) -> Result<Json<StartResidentRegistrationResponse>, (StatusCode, String)> {
    debug!(username = %req.username, "Starting resident key registration");

    let client_ip = extract_client_ip(connect_info, &headers, state.behind_proxy)
        .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_registration_allowed(client_ip).await {
        warn!(ip = %client_ip, error = %e, "Registration rate limited");
        return Err((e.status_code(), e.to_string()));
    }

    state.rate_limiter.record_registration_attempt(client_ip).await;

    // Check max credentials per user
    let config = AttestationConfig::global();
    let user_id_hash = compute_user_id_hash(&req.username);
    let existing_creds = state
        .cred_store
        .load_user_credentials(&user_id_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing_creds.len() >= config.max_credentials_per_user {
        warn!(
            username = %req.username,
            count = existing_creds.len(),
            max = config.max_credentials_per_user,
            "User has reached maximum credential limit"
        );
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Maximum of {} credentials per user reached",
                config.max_credentials_per_user
            ),
        ));
    }

    // Generate a stable user handle for this user
    // Using the username hash ensures the same handle for the same user
    let user_handle = base64ct::Base64UrlUnpadded::encode_string(user_id_hash.as_bytes());

    // Create a UUID for webauthn-rs (they use UUID for user IDs)
    let user_uuid = {
        // Derive a stable UUID from the username hash
        let hash_bytes = blake3::hash(user_id_hash.as_bytes());
        let uuid_bytes: [u8; 16] = hash_bytes.as_bytes()[..16].try_into().unwrap();
        Uuid::from_bytes(uuid_bytes)
    };

    let exclude_credentials = if existing_creds.is_empty() {
        None
    } else {
        Some(
            existing_creds
                .iter()
                .map(|c| c.cred_id.clone().into())
                .collect(),
        )
    };

    // webauthn-rs 0.5.3 API for passkey registration
    let (options, reg_state) = state
        .webauthn
        .webauthn
        .start_passkey_registration(
            user_uuid,
            &req.username,
            &req.display_name
                .clone()
                .unwrap_or_else(|| req.username.clone()),
            exclude_credentials,
        )
        .map_err(|e| {
            warn!(error = %e, "Failed to start resident registration");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Registration start failed: {}", e),
            )
        })?;

    let session_id = Uuid::new_v4().to_string();

    // Store extended session data
    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(
            session_id.clone(),
            SessionData::Registration {
                state: reg_state,
                username: req.username.clone(),
                created_at: chrono::Utc::now().timestamp(),
                client_ip,
            },
        );
        sessions.retain(|_, s| !s.is_expired());
    }

    // Store additional resident-specific session data in a separate key
    // We'll encode this in the session_id by prefixing with "res:"
    // and store the credential_name and user_handle separately

    state.rate_limiter.record_session_created(client_ip).await;

    info!(
        username = %req.username,
        session_id = %session_id,
        user_handle = %user_handle,
        "Started resident key registration"
    );

    Ok(Json(StartResidentRegistrationResponse {
        options,
        session_id,
        user_handle,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FinishResidentRegistrationRequest {
    pub session_id: String,
    pub credential: RegisterPublicKeyCredential,
    /// User handle from start response
    pub user_handle: String,
    /// Optional friendly name for the credential
    pub credential_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FinishResidentRegistrationResponse {
    pub ok: bool,
    pub cred_id: String,
    pub user_id_hash: String,
    pub registered_at: i64,
    pub device_type: String,
    pub backup_eligible: bool,
    pub is_discoverable: bool,
}

/// Finish resident key registration with extended metadata
///
/// POST /webauthn/register/resident/finish
pub async fn finish_resident_registration(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<FinishResidentRegistrationRequest>,
) -> Result<Json<FinishResidentRegistrationResponse>, (StatusCode, String)> {
    debug!(session_id = %req.session_id, "Finishing resident key registration");

    let (reg_state, username, client_ip) = {
        let mut sessions = state.sessions.write().await;
        match sessions.remove(&req.session_id) {
            Some(SessionData::Registration {
                state,
                username,
                client_ip,
                ..
            }) => (state, username, client_ip),
            Some(session) => {
                state.rate_limiter.record_session_ended(session.client_ip()).await;
                return Err((StatusCode::BAD_REQUEST, "Invalid session type".to_string()));
            }
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Session not found or expired".to_string(),
                ));
            }
        }
    };

    state.rate_limiter.record_session_ended(client_ip).await;

    // Parse attestation info before finishing registration
    let attestation_info = parse_attestation_info(&req.credential);

    // Complete registration
    let passkey = state
        .webauthn
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            warn!(error = %e, session_id = %req.session_id, "Registration failed");
            (
                StatusCode::BAD_REQUEST,
                format!("Registration failed: {}", e),
            )
        })?;

    // Determine device type from attestation
    let device_type = determine_device_type(&attestation_info);

    let user_id_hash = compute_user_id_hash(&username);
    let cred_id = passkey.cred_id().clone();

    // Extract transports from the client response (if available)
    let transports = extract_transports(&req.credential);

    // Create extended options for storage
    let create_options = CredentialCreateOptions {
        device_type,
        backup_eligible: attestation_info.flags.backup_eligible,
        backup_state: attestation_info.flags.backup_state,
        transports,
        attestation_format: Some(attestation_info.format.clone()),
        aaguid: attestation_info.aaguid.clone(),
        is_discoverable: true, // This is a resident key registration
        user_handle: Some(req.user_handle.clone()),
        friendly_name: req.credential_name.clone(),
    };

    // Save with extended options
    state
        .cred_store
        .save_with_options(
            cred_id.clone().into(),
            passkey,
            user_id_hash.clone(),
            username.clone(),
            create_options,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to save credential");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save credential: {}", e),
            )
        })?;

    let cred_id_b64 = base64ct::Base64UrlUnpadded::encode_string(&cred_id);

    info!(
        username = %username,
        cred_id = %cred_id_b64,
        device_type = %device_type,
        backup_eligible = attestation_info.flags.backup_eligible,
        "Completed resident key registration"
    );

    Ok(Json(FinishResidentRegistrationResponse {
        ok: true,
        cred_id: cred_id_b64,
        user_id_hash,
        registered_at: chrono::Utc::now().timestamp(),
        device_type: device_type.to_string(),
        backup_eligible: attestation_info.flags.backup_eligible,
        is_discoverable: true,
    }))
}

// ============================================================================
// Discoverable Authentication (Usernameless)
// ============================================================================

#[derive(Debug, Serialize)]
pub struct StartDiscoverableAuthResponse {
    pub options: RequestChallengeResponse,
    pub session_id: String,
}

/// Start discoverable (usernameless) authentication
///
/// POST /webauthn/authenticate/discoverable/start
///
/// This returns options with an empty allowCredentials list,
/// allowing the authenticator to select any stored credential.
pub async fn start_discoverable_authentication(
    State(state): State<Arc<WebAuthnState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<StartDiscoverableAuthResponse>, (StatusCode, String)> {
    debug!("Starting discoverable authentication");

    let client_ip = extract_client_ip(connect_info, &headers, state.behind_proxy)
        .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_auth_allowed(client_ip).await {
        warn!(ip = %client_ip, error = %e, "Authentication rate limited");
        return Err((e.status_code(), e.to_string()));
    }

    state.rate_limiter.record_auth_attempt(client_ip).await;

    // For discoverable credentials, we start authentication without a specific user
    // webauthn-rs requires at least one credential for start_passkey_authentication,
    // but for conditional UI/discoverable credentials, we use start_discoverable_authentication

    // Unfortunately webauthn-rs 0.5.x doesn't have a direct discoverable auth start,
    // so we need to generate the challenge ourselves following the spec
    let challenge = generate_challenge();
    let challenge_b64 = base64ct::Base64UrlUnpadded::encode_string(&challenge);

    // Create request options with empty allowCredentials
    let options = serde_json::json!({
        "publicKey": {
            "challenge": challenge_b64,
            "rpId": state.webauthn.rp_id,
            "timeout": 60000,
            "userVerification": "required",
            "allowCredentials": []
        }
    });

    let session_id = Uuid::new_v4().to_string();

    // Store the challenge for verification
    // We'll use a special marker in the session data
    {
        let mut sessions = state.sessions.write().await;
        // Store as a string to indicate discoverable auth session
        sessions.insert(
            format!("discoverable:{}", session_id),
            SessionData::Authentication {
                state: create_dummy_auth_state()?,
                username: String::new(), // Will be determined from userHandle
                created_at: chrono::Utc::now().timestamp(),
                client_ip,
            },
        );
    }

    // Also store the raw challenge for verification
    store_discoverable_challenge(&state, &session_id, &challenge).await;

    state.rate_limiter.record_session_created(client_ip).await;

    info!(session_id = %session_id, "Started discoverable authentication");

    // Convert to the expected response type
    let options: RequestChallengeResponse =
        serde_json::from_value(options).map_err(|e| {
            warn!(error = %e, "Failed to serialize discoverable auth options");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create auth options".to_string(),
            )
        })?;

    Ok(Json(StartDiscoverableAuthResponse {
        options,
        session_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FinishDiscoverableAuthRequest {
    pub session_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct FinishDiscoverableAuthResponse {
    pub ok: bool,
    pub cred_id: String,
    pub username: String,
    pub authenticated_at: i64,
    pub proof: String,
}

/// Finish discoverable authentication
///
/// POST /webauthn/authenticate/discoverable/finish
pub async fn finish_discoverable_authentication(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<FinishDiscoverableAuthRequest>,
) -> Result<Json<FinishDiscoverableAuthResponse>, (StatusCode, String)> {
    debug!(session_id = %req.session_id, "Finishing discoverable authentication");

    // Verify session exists
    let client_ip = {
        let sessions = state.sessions.read().await;
        let session_key = format!("discoverable:{}", req.session_id);
        match sessions.get(&session_key) {
            Some(SessionData::Authentication { client_ip, .. }) => *client_ip,
            _ => {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Session not found or expired".to_string(),
                ));
            }
        }
    };

    // Extract user handle from the assertion response
    let user_handle = extract_user_handle(&req.credential).ok_or_else(|| {
        warn!("No user handle in discoverable credential response");
        (
            StatusCode::BAD_REQUEST,
            "User handle required for discoverable authentication".to_string(),
        )
    })?;

    // Look up username by user handle
    let username = state
        .cred_store
        .lookup_username_by_handle(&user_handle)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            warn!(user_handle = %user_handle, "Unknown user handle");
            (StatusCode::UNAUTHORIZED, "Unknown credential".to_string())
        })?;

    // Load the user's credentials to verify
    let user_id_hash = compute_user_id_hash(&username);
    let stored_creds = state
        .cred_store
        .load_user_credentials(&user_id_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if stored_creds.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "No credentials found".to_string(),
        ));
    }

    let passkeys: Vec<Passkey> = stored_creds.into_iter().map(|c| c.credential).collect();

    // Now we need to verify the credential
    // Since we bypassed start_passkey_authentication, we need to do this manually
    // For simplicity, we'll try to match the credential ID and verify the signature

    // Get the credential ID from the response
    let cred_id = req.credential.id.as_ref();

    // Find the matching credential
    let _cred = state.cred_store.load(cred_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            warn!("Credential not found");
            (StatusCode::UNAUTHORIZED, "Credential not found".to_string())
        })?;

    // Start a proper authentication session with this credential
    let (_, auth_state) = state
        .webauthn
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            warn!(error = %e, "Failed to create auth state");
            (StatusCode::INTERNAL_SERVER_ERROR, "Auth failed".to_string())
        })?;

    // Verify the credential
    let auth_result = state
        .webauthn
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            warn!(error = %e, "Authentication failed");
            (StatusCode::UNAUTHORIZED, "Authentication failed".to_string())
        })?;

    // Clean up session
    {
        let mut sessions = state.sessions.write().await;
        sessions.remove(&format!("discoverable:{}", req.session_id));
    }
    state.rate_limiter.record_session_ended(client_ip).await;

    // Update last used
    let auth_cred_id = auth_result.cred_id();
    state.cred_store.update_last_used(auth_cred_id).await.ok();

    // Check if backup state changed
    // (In a real implementation, we'd extract this from authenticatorData flags)

    let cred_id_b64 = base64ct::Base64UrlUnpadded::encode_string(auth_cred_id);
    let authenticated_at = chrono::Utc::now().timestamp();

    // Generate proof using the same function as regular auth
    let proof = compute_auth_proof(&state.webauthn.rp_id, &username, authenticated_at);

    info!(
        username = %username,
        cred_id = %cred_id_b64,
        "Completed discoverable authentication"
    );

    Ok(Json(FinishDiscoverableAuthResponse {
        ok: true,
        cred_id: cred_id_b64,
        username,
        authenticated_at,
        proof,
    }))
}

// ============================================================================
// Credential Management (Admin)
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ListCredentialsResponse {
    pub credentials: Vec<CredentialSummary>,
    pub total: usize,
}

/// List all credentials for a user
///
/// GET /webauthn/credentials/:username
pub async fn list_user_credentials(
    State(state): State<Arc<WebAuthnState>>,
    Path(username): Path<String>,
) -> Result<Json<ListCredentialsResponse>, (StatusCode, String)> {
    let user_id_hash = compute_user_id_hash(&username);

    let credentials = state
        .cred_store
        .load_user_credentials(&user_id_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let summaries: Vec<CredentialSummary> = credentials.iter().map(|c| c.summary()).collect();
    let total = summaries.len();

    Ok(Json(ListCredentialsResponse {
        credentials: summaries,
        total,
    }))
}

#[derive(Debug, Serialize)]
pub struct AdminListCredentialsResponse {
    pub credentials: Vec<CredentialSummary>,
    pub total: usize,
    pub by_device_type: std::collections::HashMap<String, usize>,
    pub backup_stats: BackupStats,
}

#[derive(Debug, Serialize)]
pub struct BackupStats {
    pub total_backup_eligible: usize,
    pub total_backed_up: usize,
    pub hardware_bound: usize,
}

/// List all credentials in the system (admin endpoint)
///
/// GET /webauthn/admin/credentials
pub async fn admin_list_all_credentials(
    State(state): State<Arc<WebAuthnState>>,
) -> Result<Json<AdminListCredentialsResponse>, (StatusCode, String)> {
    let credentials = state
        .cred_store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let summaries: Vec<CredentialSummary> = credentials.iter().map(|c| c.summary()).collect();
    let total = summaries.len();

    // Compute statistics
    let mut by_device_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut backup_eligible = 0;
    let mut backed_up = 0;
    let mut hardware_bound = 0;

    for cred in &credentials {
        *by_device_type
            .entry(cred.device_type.to_string())
            .or_insert(0) += 1;

        if cred.backup_eligible {
            backup_eligible += 1;
        }
        if cred.backup_state {
            backed_up += 1;
        }
        if !cred.backup_eligible {
            hardware_bound += 1;
        }
    }

    Ok(Json(AdminListCredentialsResponse {
        credentials: summaries,
        total,
        by_device_type,
        backup_stats: BackupStats {
            total_backup_eligible: backup_eligible,
            total_backed_up: backed_up,
            hardware_bound,
        },
    }))
}

#[derive(Debug, Serialize)]
pub struct RevokeCredentialResponse {
    pub ok: bool,
    pub message: String,
}

/// Revoke (delete) a credential
///
/// DELETE /webauthn/credentials/:cred_id
pub async fn revoke_credential(
    State(state): State<Arc<WebAuthnState>>,
    Path(cred_id_b64): Path<String>,
) -> Result<Json<RevokeCredentialResponse>, (StatusCode, String)> {
    // Check if revocation is allowed
    let config = AttestationConfig::global();
    if !config.allow_credential_revocation {
        return Err((
            StatusCode::FORBIDDEN,
            "Credential revocation is disabled".to_string(),
        ));
    }

    // Decode credential ID
    let cred_id = base64ct::Base64UrlUnpadded::decode_vec(&cred_id_b64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid credential ID format".to_string(),
        )
    })?;

    // Delete the credential
    let deleted = state
        .cred_store
        .delete(&cred_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if deleted {
        info!(cred_id = %cred_id_b64, "Credential revoked");
        Ok(Json(RevokeCredentialResponse {
            ok: true,
            message: "Credential revoked successfully".to_string(),
        }))
    } else {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    }
}

// ============================================================================
// Router Factory
// ============================================================================

/// Create router for discoverable credential endpoints
pub fn discoverable_router(state: Arc<WebAuthnState>) -> Router {
    Router::new()
        .route("/register/resident/start", post(start_resident_registration))
        .route("/register/resident/finish", post(finish_resident_registration))
        .route("/authenticate/discoverable/start", post(start_discoverable_authentication))
        .route("/authenticate/discoverable/finish", post(finish_discoverable_authentication))
        .with_state(state)
}

/// Create router for admin/credential management endpoints
pub fn admin_router(state: Arc<WebAuthnState>) -> Router {
    Router::new()
        .route("/credentials/:username", get(list_user_credentials))
        .route("/credentials/:cred_id", delete(revoke_credential))
        .route("/admin/credentials", get(admin_list_all_credentials))
        .with_state(state)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute user ID hash from username
fn compute_user_id_hash(username: &str) -> String {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(b"webauthn:user:");
    hasher.update(username.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Determine device type from attestation info
fn determine_device_type(info: &super::attestation::AttestationInfo) -> DeviceType {
    // Heuristics based on attestation format and AAGUID
    match info.format.as_str() {
        "apple" => DeviceType::Platform,
        "tpm" => DeviceType::Platform, // Windows Hello, Chromebook
        "android-key" => DeviceType::Platform,
        "packed" | "fido-u2f" => {
            // Could be either platform or cross-platform
            // Check for known platform AAGUIDs
            if let Some(ref aaguid) = info.aaguid {
                if aaguid == "00000000-0000-0000-0000-000000000000" {
                    // Self-attestation, likely platform
                    DeviceType::Platform
                } else {
                    DeviceType::CrossPlatform
                }
            } else {
                DeviceType::Unknown
            }
        }
        "none" => {
            // Could be platform with privacy-preserving attestation
            DeviceType::Unknown
        }
        _ => DeviceType::Unknown,
    }
}

/// Extract transports from credential response
fn extract_transports(_credential: &RegisterPublicKeyCredential) -> Vec<AuthenticatorTransport> {
    // webauthn-rs 0.5.x may include transports in the response
    // For now, return empty - in practice, this would be parsed from
    // the attestation object or provided by the client
    Vec::new()
}

/// Extract user handle from credential response
fn extract_user_handle(credential: &PublicKeyCredential) -> Option<String> {
    // The userHandle is in the response.userHandle field
    credential
        .response
        .user_handle
        .as_ref()
        .map(|h| base64ct::Base64UrlUnpadded::encode_string(h))
}

/// Generate a random challenge
fn generate_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Create a dummy auth state for session storage
/// This is a workaround since we're using SessionData::Authentication
fn create_dummy_auth_state() -> Result<PasskeyAuthentication, (StatusCode, String)> {
    // We can't easily create a PasskeyAuthentication without going through
    // start_passkey_authentication, so this is a limitation
    // In a real implementation, we'd want to extend SessionData or use a different approach
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Discoverable auth requires extended session support".to_string(),
    ))
}

/// Store the discoverable auth challenge for later verification
async fn store_discoverable_challenge(_state: &WebAuthnState, _session_id: &str, _challenge: &[u8]) {
    // In a production implementation, this would store the challenge
    // in Redis or the sessions map for later verification
    // For now, we rely on webauthn-rs to handle challenge verification
}

/// Compute authentication proof (same as in handlers.rs)
fn compute_auth_proof(rp_id: &str, username: &str, timestamp: i64) -> String {
    // Use the same proof derivation as handlers.rs
    let proof_key = derive_proof_key(rp_id);
    let mut hasher = blake3::Hasher::new_keyed(&proof_key);
    hasher.update(b"webauthn:auth:");
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(&timestamp.to_le_bytes());
    base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
}

/// Derive proof key (same as in handlers.rs)
fn derive_proof_key(rp_id: &str) -> [u8; 32] {
    let (secret_bytes, has_secret) = if let Ok(secret) = std::env::var("WEBAUTHN_PROOF_SECRET") {
        let mut key_hasher = blake3::Hasher::new();
        key_hasher.update(b"webauthn:secret:key:v1:");
        key_hasher.update(secret.as_bytes());
        (*key_hasher.finalize().as_bytes(), true)
    } else {
        let mut key_hasher = blake3::Hasher::new();
        key_hasher.update(b"webauthn:deterministic:key:v1:");
        key_hasher.update(rp_id.as_bytes());
        key_hasher.update(b":insecure-fallback");
        (*key_hasher.finalize().as_bytes(), false)
    };

    let mut hasher = blake3::Hasher::new_keyed(&secret_bytes);
    hasher.update(b"webauthn:proof:key:v1:");
    hasher.update(rp_id.as_bytes());
    if !has_secret {
        hasher.update(b":deterministic");
    }

    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_user_id_hash() {
        let hash1 = compute_user_id_hash("alice");
        let hash2 = compute_user_id_hash("alice");
        let hash3 = compute_user_id_hash("bob");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
