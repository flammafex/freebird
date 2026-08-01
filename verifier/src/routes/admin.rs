// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Admin API for the Freebird verifier service
//!
//! This module provides administrative endpoints for:
//! - Health monitoring and service identification
//! - Verification statistics and metrics
//! - Trusted issuer management
//! - Replay cache management
//! - Configuration viewing
//!
//! # Security
//!
//! All endpoints require authentication via API key in the `X-Admin-Key` header.
//! The API key should be configured via the `ADMIN_API_KEY` environment variable.

use crate::readiness::{self, MetadataStatus, StoreHealth, TokenFamily};
use crate::replay_authority::ReplayAuthorityHealth;
use crate::routes::admin_rate_limit::AdminRateLimiter;
use crate::store::SpendStore;
use axum::{
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use base64ct::Encoding;
use freebird_common::tls_enforcement::ValidatedClientIp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn};

// Issuer metadata types are owned by the metadata module but remain available
// at their established public admin paths.
pub use crate::metadata::{IssuerInfo, PublicIssuerKey};

// ============================================================================
// Admin State
// ============================================================================

/// State for the admin API
#[derive(Clone)]
pub struct AdminState {
    /// Reference to the issuers map
    pub issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    /// Reference to the spend store
    pub store: Arc<dyn SpendStore>,
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
    /// Server start time for uptime calculation
    pub start_time: Instant,
    /// Configuration values
    pub config: VerifierConfig,
    pub metadata: Arc<RwLock<HashMap<String, MetadataStatus>>>,
    pub accepted_token_families: Vec<TokenFamily>,
    pub store_health: StoreHealth,
    pub replay_authority: Arc<ReplayAuthorityHealth>,
}

/// Derive a session signing key from the admin API key using HKDF-SHA256.
pub fn derive_session_key(api_key: &str) -> [u8; 32] {
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

/// Verifier configuration (for /admin/config endpoint)
#[derive(Clone, Debug, Serialize)]
pub struct VerifierConfig {
    pub verifier_id: String,
    pub audience: String,
    pub epoch_duration_sec: u64,
    pub epoch_retention: u32,
    pub refresh_interval_min: u64,
    pub store_backend: String,
    pub issuer_urls: Vec<String>,
    pub accepted_token_versions: Vec<String>,
    pub graph_issuer_urls: Vec<String>,
    pub replay_authority_probe_interval_secs: u64,
    pub replay_authority_max_staleness_secs: u64,
}

// ============================================================================
// Error Types
// ============================================================================

/// Admin API errors
#[derive(Debug)]
pub enum AdminError {
    Unauthorized,
    RateLimited(u64),
    IssuerNotFound(String),
    InvalidRequest(String),
    Internal(String),
}

impl IntoResponse for AdminError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AdminError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AdminError::RateLimited(secs) => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("rate limited, try again in {} seconds", secs),
            ),
            AdminError::IssuerNotFound(id) => {
                (StatusCode::NOT_FOUND, format!("issuer not found: {}", id))
            }
            AdminError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AdminError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = serde_json::json!({ "error": message });
        (status, Json(body)).into_response()
    }
}

// ============================================================================
// Response Types
// ============================================================================

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service type identifier for UI detection
    pub service: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub store_backend: String,
    pub issuers_loaded: usize,
}

/// Verification statistics response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub current_epoch: u32,
    pub valid_epoch_range: (u32, u32),
    pub issuers_loaded: usize,
    pub store_backend: String,
    pub timestamp: u64,
}

/// Configuration response
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub verifier_id: String,
    pub audience: String,
    pub epoch_duration_sec: u64,
    pub epoch_retention: u32,
    pub refresh_interval_min: u64,
    pub store_backend: String,
    pub issuer_urls: Vec<String>,
}

/// Issuer summary for list view
#[derive(Debug, Serialize)]
pub struct IssuerSummary {
    pub issuer_id: String,
    pub kid: String,
    pub public_key_count: usize,
    /// First 16 chars of base64-encoded pubkey for identification
    pub pubkey_preview: String,
    /// Seconds since last refresh (if known)
    pub age_secs: Option<u64>,
}

/// List issuers response
#[derive(Debug, Serialize)]
pub struct ListIssuersResponse {
    pub issuers: Vec<IssuerSummary>,
    pub total: usize,
}

/// Detailed issuer response
#[derive(Debug, Serialize)]
pub struct IssuerDetailsResponse {
    pub issuer_id: String,
    pub kid: String,
    pub pubkey_b64: String,
    pub context: String,
    pub public_key_ids: Vec<String>,
    pub age_secs: Option<u64>,
}

/// Cache stats response
#[derive(Debug, Serialize)]
pub struct CacheStatsResponse {
    pub store_backend: String,
    pub status: String,
}

/// Cache clear response
#[derive(Debug, Serialize)]
pub struct CacheClearResponse {
    pub ok: bool,
    pub message: String,
}

/// Issuer refresh response
#[derive(Debug, Serialize)]
pub struct IssuerRefreshResponse {
    pub ok: bool,
    pub issuer_id: String,
    pub message: String,
}

// ============================================================================
// Router Builder
// ============================================================================

/// Build the admin router
pub fn admin_router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(admin_ui_handler))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/health", get(health_handler))
        .route("/readiness", get(readiness_handler))
        .route("/stats", get(stats_handler))
        .route("/config", get(config_handler))
        .route("/metrics", get(metrics_handler))
        .route("/issuers", get(list_issuers_handler))
        .route("/issuers/{issuer_id}", get(get_issuer_handler))
        .route("/issuers/{issuer_id}/refresh", post(refresh_issuer_handler))
        .route("/cache/stats", get(cache_stats_handler))
        .route("/cache/clear", post(cache_clear_handler))
        .with_state(state)
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
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Option<IpAddr> {
    let _ = (headers, behind_proxy, connect_info);
    validated_ip.map(|Extension(ip)| ip.0)
}

/// Verify authentication via session cookie or X-Admin-Key header with rate limiting
async fn verify_api_key(
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
    validated_ip: Option<Extension<ValidatedClientIp>>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);

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
// Handlers
// ============================================================================

/// Health check endpoint - returns service type for UI detection
pub async fn health_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<HealthResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    let issuers = state.issuers.read().await;
    let uptime = state.start_time.elapsed().as_secs();

    Ok(Json(HealthResponse {
        service: "verifier".to_string(),
        status: "ok".to_string(),
        uptime_seconds: uptime,
        store_backend: state.config.store_backend.clone(),
        issuers_loaded: issuers.len(),
    }))
}

/// Detailed readiness is deliberately only available behind the admin auth.
pub async fn readiness_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;
    let issuers = state.issuers.read().await.clone();
    let metadata = state.metadata.read().await.clone();
    let report = readiness::evaluate(
        &state.store_health,
        &issuers,
        &metadata,
        &state.config.issuer_urls,
        &state.accepted_token_families,
        std::time::Duration::from_secs(state.config.refresh_interval_min * 60),
        Some(&state.replay_authority),
    )
    .await;
    Ok(Json(
        serde_json::json!({"status": if report.ready() { "ready" } else { "not_ready" }, "failures": report.failures}),
    ))
}

/// Get verification statistics
pub async fn stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<StatsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    let issuers = state.issuers.read().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let current_epoch = (now / state.config.epoch_duration_sec) as u32;
    let min_valid_epoch = current_epoch.saturating_sub(state.config.epoch_retention);

    info!("Admin: retrieved verifier stats");

    Ok(Json(StatsResponse {
        current_epoch,
        valid_epoch_range: (min_valid_epoch, current_epoch),
        issuers_loaded: issuers.len(),
        store_backend: state.config.store_backend.clone(),
        timestamp: now,
    }))
}

/// Get verifier configuration
pub async fn config_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<ConfigResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    info!("Admin: retrieved verifier config");

    Ok(Json(ConfigResponse {
        verifier_id: state.config.verifier_id.clone(),
        audience: state.config.audience.clone(),
        epoch_duration_sec: state.config.epoch_duration_sec,
        epoch_retention: state.config.epoch_retention,
        refresh_interval_min: state.config.refresh_interval_min,
        store_backend: state.config.store_backend.clone(),
        issuer_urls: state.config.issuer_urls.clone(),
    }))
}

/// List all trusted issuers
pub async fn list_issuers_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<ListIssuersResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    let issuers = state.issuers.read().await;

    let issuer_list: Vec<IssuerSummary> = issuers
        .iter()
        .map(|(id, info)| {
            let pubkey_preview = base64ct::Base64UrlUnpadded::encode_string(&info.pubkey_bytes);
            let pubkey_preview = if pubkey_preview.len() > 16 {
                pubkey_preview[..16].to_string()
            } else {
                pubkey_preview
            };

            let age_secs = info.last_refreshed.map(|t| t.elapsed().as_secs());

            IssuerSummary {
                issuer_id: id.clone(),
                kid: info.kid.clone(),
                public_key_count: info.public_keys.len(),
                pubkey_preview,
                age_secs,
            }
        })
        .collect();

    let total = issuer_list.len();

    info!("Admin: listed {} issuers", total);

    Ok(Json(ListIssuersResponse {
        issuers: issuer_list,
        total,
    }))
}

/// Get detailed information about a specific issuer
pub async fn get_issuer_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    Path(issuer_id): Path<String>,
) -> Result<Json<IssuerDetailsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    let issuers = state.issuers.read().await;

    let info = issuers
        .get(&issuer_id)
        .ok_or_else(|| AdminError::IssuerNotFound(issuer_id.clone()))?;

    let pubkey_b64 = base64ct::Base64UrlUnpadded::encode_string(&info.pubkey_bytes);
    let context = String::from_utf8_lossy(&info.ctx).to_string();
    let public_key_ids = info
        .public_keys
        .values()
        .map(|key| key.token_key_id_hex.clone())
        .collect();
    let age_secs = info.last_refreshed.map(|t| t.elapsed().as_secs());

    info!("Admin: retrieved issuer details for {}", issuer_id);

    Ok(Json(IssuerDetailsResponse {
        issuer_id,
        kid: info.kid.clone(),
        pubkey_b64,
        context,
        public_key_ids,
        age_secs,
    }))
}

/// Force refresh issuer metadata
/// Note: This is a placeholder - actual refresh requires access to the refresh mechanism
pub async fn refresh_issuer_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    Path(issuer_id): Path<String>,
) -> Result<Json<IssuerRefreshResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    // Check if issuer exists
    let issuers = state.issuers.read().await;
    if !issuers.contains_key(&issuer_id) {
        return Err(AdminError::IssuerNotFound(issuer_id));
    }
    drop(issuers);

    // Note: Actual refresh would need to trigger the background refresh task
    // For now, we just acknowledge the request
    info!("Admin: refresh requested for issuer {}", issuer_id);

    Ok(Json(IssuerRefreshResponse {
        ok: true,
        issuer_id,
        message: "Refresh will occur on next background cycle".to_string(),
    }))
}

/// Get cache statistics
pub async fn cache_stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<CacheStatsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    info!("Admin: retrieved cache stats");

    Ok(Json(CacheStatsResponse {
        store_backend: state.config.store_backend.clone(),
        status: "operational".to_string(),
    }))
}

/// Clear the replay cache (use with caution!)
pub async fn cache_clear_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<Json<CacheClearResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    // Note: The SpendStore trait doesn't have a clear method
    // This would need to be added to support cache clearing
    warn!("Admin: cache clear requested (not implemented for safety)");

    Ok(Json(CacheClearResponse {
        ok: false,
        message:
            "Cache clearing is disabled for safety. Restart the service to clear in-memory cache."
                .to_string(),
    }))
}

/// Prometheus metrics endpoint
pub async fn metrics_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> Result<String, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy, connect_info, validated_ip);
    verify_api_key(&headers, &state, client_ip).await?;

    let issuers = state.issuers.read().await;
    let uptime = state.start_time.elapsed().as_secs();

    let mut output = String::new();

    macro_rules! metric {
        ($name:expr, $type:expr, $help:expr, $value:expr) => {
            output.push_str(&format!(
                "# HELP {} {}\n# TYPE {} {}\n{} {}\n",
                $name, $help, $name, $type, $name, $value
            ));
        };
    }

    metric!(
        "freebird_verifier_uptime_seconds",
        "gauge",
        "Verifier uptime in seconds",
        uptime
    );
    metric!(
        "freebird_verifier_issuers_loaded",
        "gauge",
        "Number of trusted issuers loaded",
        issuers.len()
    );

    output.push_str(&freebird_common::metrics::encode_metrics());

    info!("Admin: retrieved Prometheus metrics");

    Ok(output)
}
