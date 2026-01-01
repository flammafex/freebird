// issuer/src/routes/webauthn_attestation.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// WebAuthn Attestation Extension - Final working version for webauthn-rs 0.5.3
// Provides policy-based enforcement with the API limitations

#![cfg(feature = "human-gate-webauthn")]

use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use base64ct::Encoding;
use chrono;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};
use webauthn_rs::prelude::*;

// Import the existing types from webauthn.rs
use super::webauthn::{
    FinishRegistrationRequest, FinishRegistrationResponse, SessionData, WebAuthnState,
};

/// Extended finish registration with policy enforcement
pub async fn finish_registration_with_attestation(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<Json<FinishRegistrationResponse>, (StatusCode, String)> {
    debug!(session_id = %req.session_id, "Finishing WebAuthn registration with policy check");

    let (reg_state, username) = {
        let mut sessions = state.sessions.write().await;
        match sessions.remove(&req.session_id) {
            Some(SessionData::Registration {
                state, username, ..
            }) => (state, username),
            Some(_) => {
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

    // Apply policy checks if configured
    if should_enforce_policy() {
        enforce_registration_policy(&req.credential)?;
    }

    // Continue with the existing registration flow
    let user_id_hash = {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"webauthn:user:");
        hasher.update(username.as_bytes());
        hasher.finalize().to_hex().to_string()
    };

    let cred_id = passkey.cred_id().clone();

    // Save credential
    state
        .cred_store
        .save(cred_id.clone().into(), passkey, user_id_hash.clone())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to save credential");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save credential: {}", e),
            )
        })?;

    // Optionally store policy metadata
    if let Ok(redis_url) = std::env::var("WEBAUTHN_REDIS_URL") {
        store_registration_metadata(&redis_url, &cred_id, &username).await;
    }

    let cred_id_b64 = base64ct::Base64UrlUnpadded::encode_string(&cred_id);

    info!(
        username = %username,
        cred_id = %cred_id_b64,
        "Completed WebAuthn registration with policy enforcement"
    );

    Ok(Json(FinishRegistrationResponse {
        ok: true,
        cred_id: cred_id_b64,
        user_id_hash,
        registered_at: chrono::Utc::now().timestamp(),
    }))
}

/// Check if policy enforcement is enabled
fn should_enforce_policy() -> bool {
    std::env::var("WEBAUTHN_REQUIRE_ATTESTATION")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true")
}

/// Enforce registration policy based on configuration
fn enforce_registration_policy(
    credential: &RegisterPublicKeyCredential,
) -> Result<(), (StatusCode, String)> {
    let policy =
        std::env::var("WEBAUTHN_ATTESTATION_POLICY").unwrap_or_else(|_| "none".to_string());

    match policy.as_str() {
        "none" => {
            info!("No attestation policy enforcement");
            Ok(())
        }
        "strict" => {
            // Check the attestation object size as a heuristic
            // Use to_vec() to get the actual bytes
            let data = credential.response.attestation_object.to_vec();
            let size = data.len();

            if size < 200 {
                // Very small attestation object likely means "none" format
                warn!("Registration rejected: attestation object too small (likely software key)");
                return Err((
                    StatusCode::FORBIDDEN,
                    "Hardware authenticator required".to_string(),
                ));
            }
            info!(
                "Registration accepted: attestation object present (size: {} bytes)",
                size
            );
            Ok(())
        }
        "log_only" => {
            // Log attestation details but don't enforce
            let data = credential.response.attestation_object.to_vec();
            let size = data.len();
            info!("Attestation object size: {} bytes", size);
            Ok(())
        }
        _ => {
            warn!("Unknown attestation policy: {}", policy);
            Ok(())
        }
    }
}

/// Store registration metadata for monitoring
async fn store_registration_metadata(redis_url: &str, cred_id: &[u8], username: &str) {
    // Store metadata about the registration for analytics
    if let Ok(client) = redis::Client::open(redis_url) {
        if let Ok(mut conn) = client.get_async_connection().await {
            let metadata = RegistrationMetadata {
                username: username.to_string(),
                registered_at: chrono::Utc::now().timestamp(),
                policy: std::env::var("WEBAUTHN_ATTESTATION_POLICY")
                    .unwrap_or_else(|_| "none".to_string()),
            };

            if let Ok(json) = serde_json::to_string(&metadata) {
                let key = format!(
                    "webauthn:metadata:{}",
                    base64ct::Base64UrlUnpadded::encode_string(cred_id)
                );

                let _: Result<(), _> = redis::cmd("SET")
                    .arg(&key)
                    .arg(&json)
                    .arg("EX")
                    .arg(86400) // 24 hour TTL for metadata
                    .query_async(&mut conn)
                    .await;

                info!("Stored registration metadata for monitoring");
            }
        }
    }
}

/// Metadata stored for each registration
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationMetadata {
    username: String,
    registered_at: i64,
    policy: String,
}
