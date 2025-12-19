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

use crate::routes::admin_rate_limit::AdminRateLimiter;
use crate::store::SpendStore;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use base64ct::Encoding;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ============================================================================
// Issuer Info - Shared type used by both main.rs and admin
// ============================================================================

/// Information about a trusted issuer
/// This type is shared between main.rs and the admin module
#[derive(Clone, Debug)]
pub struct IssuerInfo {
    pub pubkey_bytes: Vec<u8>,
    pub kid: String,
    pub ctx: Vec<u8>,
    pub exp_sec: u64,
    /// When this issuer's metadata was last refreshed
    pub last_refreshed: Option<Instant>,
}

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
    /// Rate limiter for authentication attempts
    pub rate_limiter: AdminRateLimiter,
    /// Whether running behind a proxy (use X-Forwarded-For)
    pub behind_proxy: bool,
    /// Server start time for uptime calculation
    pub start_time: Instant,
    /// Configuration values
    pub config: VerifierConfig,
}

/// Verifier configuration (for /admin/config endpoint)
#[derive(Clone, Debug, Serialize)]
pub struct VerifierConfig {
    pub max_clock_skew_secs: i64,
    pub epoch_duration_sec: u64,
    pub epoch_retention: u32,
    pub refresh_interval_min: u64,
    pub store_backend: String,
    pub issuer_urls: Vec<String>,
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
    pub max_clock_skew_secs: i64,
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
    /// First 16 chars of base64-encoded pubkey for identification
    pub pubkey_preview: String,
    pub exp_sec: u64,
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
    pub exp_sec: u64,
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
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/config", get(config_handler))
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

/// Serve the admin UI
pub async fn admin_ui_handler() -> impl IntoResponse {
    const ADMIN_UI_HTML: &str = include_str!("../admin_ui/index.html");
    Html(ADMIN_UI_HTML)
}

// ============================================================================
// Authentication
// ============================================================================

/// Extract client IP from headers or connection info
fn extract_client_ip(headers: &HeaderMap, behind_proxy: bool) -> Option<IpAddr> {
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
    None
}

/// Verify API key using constant-time comparison with rate limiting
async fn verify_api_key(
    headers: &HeaderMap,
    state: &AdminState,
    client_ip: Option<IpAddr>,
) -> Result<(), AdminError> {
    // Use a fallback IP for rate limiting if we can't determine the real one
    let ip = client_ip.unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

    // Check if IP is currently rate-limited
    if let Err(seconds_remaining) = state.rate_limiter.check_allowed(ip).await {
        return Err(AdminError::RateLimited(seconds_remaining));
    }

    let provided_key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AdminError::Unauthorized)?;

    // Use constant-time comparison to prevent timing attacks
    let expected_bytes = state.api_key.as_bytes();
    let provided_bytes = provided_key.as_bytes();

    let is_valid = if expected_bytes.len() == provided_bytes.len() {
        expected_bytes.ct_eq(provided_bytes).into()
    } else {
        // Different lengths - still do a comparison to maintain constant time
        let dummy = vec![0u8; expected_bytes.len()];
        let _ = expected_bytes.ct_eq(&dummy);
        false
    };

    if !is_valid {
        state.rate_limiter.record_failure(ip).await;
        warn!("Invalid admin API key provided from IP: {}", ip);
        return Err(AdminError::Unauthorized);
    }

    state.rate_limiter.record_success(ip).await;
    Ok(())
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check endpoint - returns service type for UI detection
pub async fn health_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
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

/// Get verification statistics
pub async fn stats_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<StatsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
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
) -> Result<Json<ConfigResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
    verify_api_key(&headers, &state, client_ip).await?;

    info!("Admin: retrieved verifier config");

    Ok(Json(ConfigResponse {
        max_clock_skew_secs: state.config.max_clock_skew_secs,
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
) -> Result<Json<ListIssuersResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
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
                pubkey_preview,
                exp_sec: info.exp_sec,
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
    Path(issuer_id): Path<String>,
) -> Result<Json<IssuerDetailsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
    verify_api_key(&headers, &state, client_ip).await?;

    let issuers = state.issuers.read().await;

    let info = issuers
        .get(&issuer_id)
        .ok_or_else(|| AdminError::IssuerNotFound(issuer_id.clone()))?;

    let pubkey_b64 = base64ct::Base64UrlUnpadded::encode_string(&info.pubkey_bytes);
    let context = String::from_utf8_lossy(&info.ctx).to_string();
    let age_secs = info.last_refreshed.map(|t| t.elapsed().as_secs());

    info!("Admin: retrieved issuer details for {}", issuer_id);

    Ok(Json(IssuerDetailsResponse {
        issuer_id,
        kid: info.kid.clone(),
        pubkey_b64,
        context,
        exp_sec: info.exp_sec,
        age_secs,
    }))
}

/// Force refresh issuer metadata
/// Note: This is a placeholder - actual refresh requires access to the refresh mechanism
pub async fn refresh_issuer_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
) -> Result<Json<IssuerRefreshResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
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
) -> Result<Json<CacheStatsResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
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
) -> Result<Json<CacheClearResponse>, AdminError> {
    let client_ip = extract_client_ip(&headers, state.behind_proxy);
    verify_api_key(&headers, &state, client_ip).await?;

    // Note: The SpendStore trait doesn't have a clear method
    // This would need to be added to support cache clearing
    warn!("Admin: cache clear requested (not implemented for safety)");

    Ok(Json(CacheClearResponse {
        ok: false,
        message: "Cache clearing is disabled for safety. Restart the service to clear in-memory cache.".to_string(),
    }))
}
