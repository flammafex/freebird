// issuer/src/routes/webauthn.rs
// CORRECTED FOR webauthn-rs 0.5.3 API

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::webauthn_ctx::WebAuthnCtx;
use crate::webauthn_store::{InMemoryCredStore, RedisCredStore};

// ============================================================================
// State Management
// ============================================================================

#[derive(Clone)]
pub struct WebAuthnState {
    pub webauthn: Arc<WebAuthnCtx>,
    pub cred_store: CredentialStore,
    pub sessions: Arc<RwLock<HashMap<String, SessionData>>>,
}

#[derive(Clone)]
pub enum CredentialStore {
    Redis(RedisCredStore),
    InMemory(InMemoryCredStore),
}

impl CredentialStore {
    pub async fn save(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
    ) -> anyhow::Result<()> {
        match self {
            CredentialStore::Redis(store) => store.save(cred_id, credential, user_id_hash).await,
            CredentialStore::InMemory(store) => store.save(cred_id, credential, user_id_hash).await,
        }
    }

    pub async fn load(&self, cred_id: &[u8]) -> anyhow::Result<Option<crate::webauthn_store::StoredCredential>> {
        match self {
            CredentialStore::Redis(store) => store.load(cred_id).await,
            CredentialStore::InMemory(store) => store.load(cred_id).await,
        }
    }

    pub async fn load_user_credentials(&self, user_id_hash: &str) -> anyhow::Result<Vec<crate::webauthn_store::StoredCredential>> {
        match self {
            CredentialStore::Redis(store) => store.load_user_credentials(user_id_hash).await,
            CredentialStore::InMemory(store) => store.load_user_credentials(user_id_hash).await,
        }
    }

    pub async fn update_last_used(&self, cred_id: &[u8]) -> anyhow::Result<()> {
        match self {
            CredentialStore::Redis(store) => store.update_last_used(cred_id).await,
            CredentialStore::InMemory(store) => store.update_last_used(cred_id).await,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SessionData {
    Registration {
        state: PasskeyRegistration,
        username: String,
        created_at: i64,
    },
    Authentication {
        state: PasskeyAuthentication,
        username: String,
        created_at: i64,
    },
}

impl SessionData {
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        let created_at = match self {
            SessionData::Registration { created_at, .. } => *created_at,
            SessionData::Authentication { created_at, .. } => *created_at,
        };
        now - created_at > 900 // 15 minutes
    }
}

// ============================================================================
// Registration Flow
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct StartRegistrationRequest {
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StartRegistrationResponse {
    pub options: CreationChallengeResponse,
    pub session_id: String,
}

pub async fn start_registration(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<StartRegistrationRequest>,
) -> Result<Json<StartRegistrationResponse>, (StatusCode, String)> {
    debug!(username = %req.username, "Starting WebAuthn registration");

    let user_id_hash = {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"webauthn:user:");
        hasher.update(req.username.as_bytes());
        hasher.finalize().to_hex().to_string()
    };

    let existing_creds = state
        .cred_store
        .load_user_credentials(&user_id_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !existing_creds.is_empty() {
        warn!(
            username = %req.username,
            cred_count = existing_creds.len(),
            "User already has registered credentials"
        );
        return Err((
            StatusCode::CONFLICT,
            format!("User already has {} credential(s) registered", existing_creds.len()),
        ));
    }

    let exclude_credentials = if existing_creds.is_empty() {
        None
    } else {
        Some(existing_creds.iter().map(|c| c.cred_id.clone().into()).collect())
    };

    // webauthn-rs 0.5.3 API: start_passkey_registration(uuid, username, display_name, exclude)
    let (options, reg_state) = state
        .webauthn
        .webauthn
        .start_passkey_registration(
            Uuid::new_v4(),
            &req.username,
            &req.display_name.clone().unwrap_or_else(|| req.username.clone()),
            exclude_credentials,
        )
        .map_err(|e| {
            warn!(error = %e, "Failed to start registration");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Registration start failed: {}", e))
        })?;

    let session_id = uuid::Uuid::new_v4().to_string();

    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(
            session_id.clone(),
            SessionData::Registration {
                state: reg_state,
                username: req.username.clone(),
                created_at: chrono::Utc::now().timestamp(),
            },
        );
        sessions.retain(|_, session| !session.is_expired());
    }

    info!(
        username = %req.username,
        session_id = %session_id,
        "Started WebAuthn registration"
    );

    Ok(Json(StartRegistrationResponse {
        options,
        session_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FinishRegistrationRequest {
    pub session_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct FinishRegistrationResponse {
    pub ok: bool,
    pub cred_id: String,
    pub user_id_hash: String,
    pub registered_at: i64,
}

pub async fn finish_registration(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<Json<FinishRegistrationResponse>, (StatusCode, String)> {
    debug!(session_id = %req.session_id, "Finishing WebAuthn registration");

    let (reg_state, username) = {
        let mut sessions = state.sessions.write().await;
        match sessions.remove(&req.session_id) {
            Some(SessionData::Registration { state, username, .. }) => (state, username),
            Some(_) => {
                return Err((StatusCode::BAD_REQUEST, "Invalid session type".to_string()));
            }
            None => {
                return Err((StatusCode::NOT_FOUND, "Session not found or expired".to_string()));
            }
        }
    };

    let passkey = state
        .webauthn
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            warn!(error = %e, session_id = %req.session_id, "Registration failed");
            (StatusCode::BAD_REQUEST, format!("Registration failed: {}", e))
        })?;

    let user_id_hash = {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"webauthn:user:");
        hasher.update(username.as_bytes());
        hasher.finalize().to_hex().to_string()
    };

    let cred_id = passkey.cred_id().clone();
    state
        .cred_store
        .save(cred_id.clone().into(), passkey, user_id_hash.clone())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to save credential");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save credential: {}", e))
        })?;

    let cred_id_b64 = base64ct::Base64UrlUnpadded::encode_string(&cred_id);

    info!(
        username = %username,
        cred_id = %cred_id_b64,
        "Completed WebAuthn registration"
    );

    Ok(Json(FinishRegistrationResponse {
        ok: true,
        cred_id: cred_id_b64,
        user_id_hash,
        registered_at: chrono::Utc::now().timestamp(),
    }))
}

// ============================================================================
// Authentication Flow
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct StartAuthenticationRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct StartAuthenticationResponse {
    pub options: RequestChallengeResponse,
    pub session_id: String,
}

pub async fn start_authentication(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<StartAuthenticationRequest>,
) -> Result<Json<StartAuthenticationResponse>, (StatusCode, String)> {
    debug!(username = %req.username, "Starting WebAuthn authentication");

    let user_id_hash = {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"webauthn:user:");
        hasher.update(req.username.as_bytes());
        hasher.finalize().to_hex().to_string()
    };

    let stored_creds = state
        .cred_store
        .load_user_credentials(&user_id_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if stored_creds.is_empty() {
        warn!(username = %req.username, "No credentials found for user");
        return Err((StatusCode::NOT_FOUND, "User has no registered credentials".to_string()));
    }

    let passkeys: Vec<Passkey> = stored_creds
        .into_iter()
        .map(|c| c.credential)
        .collect();

    let (options, auth_state) = state
        .webauthn
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            warn!(error = %e, "Failed to start authentication");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Authentication start failed: {}", e))
        })?;

    let session_id = uuid::Uuid::new_v4().to_string();

    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(
            session_id.clone(),
            SessionData::Authentication {
                state: auth_state,
                username: req.username.clone(),
                created_at: chrono::Utc::now().timestamp(),
            },
        );
        sessions.retain(|_, session| !session.is_expired());
    }

    info!(
        username = %req.username,
        session_id = %session_id,
        "Started WebAuthn authentication"
    );

    Ok(Json(StartAuthenticationResponse {
        options,
        session_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FinishAuthenticationRequest {
    pub session_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct FinishAuthenticationResponse {
    pub ok: bool,
    pub cred_id: String,
    pub username: String,
    pub authenticated_at: i64,
    pub proof: String,
}

pub async fn finish_authentication(
    State(state): State<Arc<WebAuthnState>>,
    Json(req): Json<FinishAuthenticationRequest>,
) -> Result<Json<FinishAuthenticationResponse>, (StatusCode, String)> {
    debug!(session_id = %req.session_id, "Finishing WebAuthn authentication");

    let (auth_state, username) = {
        let mut sessions = state.sessions.write().await;
        match sessions.remove(&req.session_id) {
            Some(SessionData::Authentication { state, username, .. }) => (state, username),
            Some(_) => {
                return Err((StatusCode::BAD_REQUEST, "Invalid session type".to_string()));
            }
            None => {
                return Err((StatusCode::NOT_FOUND, "Session not found or expired".to_string()));
            }
        }
    };

    let auth_result = state
        .webauthn
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            warn!(error = %e, session_id = %req.session_id, "Authentication failed");
            (StatusCode::UNAUTHORIZED, format!("Authentication failed: {}", e))
        })?;

    let cred_id = auth_result.cred_id();
    state
        .cred_store
        .update_last_used(cred_id)
        .await
        .ok();

    let cred_id_b64 = base64ct::Base64UrlUnpadded::encode_string(cred_id);

    let proof = {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"webauthn:auth:");
        hasher.update(username.as_bytes());
        hasher.update(b":");
        hasher.update(cred_id);
        hasher.update(b":");
        hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    };

    info!(
        username = %username,
        cred_id = %cred_id_b64,
        "Completed WebAuthn authentication"
    );

    Ok(Json(FinishAuthenticationResponse {
        ok: true,
        cred_id: cred_id_b64,
        username,
        authenticated_at: chrono::Utc::now().timestamp(),
        proof,
    }))
}

// ============================================================================
// Info Endpoint
// ============================================================================

#[derive(Debug, Serialize)]
pub struct WebAuthnInfo {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
}

pub async fn webauthn_info(
    State(state): State<Arc<WebAuthnState>>,
) -> Json<WebAuthnInfo> {
    Json(WebAuthnInfo {
        rp_id: state.webauthn.rp_id.clone(),
        rp_name: state.webauthn.rp_name.clone(),
        origin: state.webauthn.rp_origin.clone(),
    })
}