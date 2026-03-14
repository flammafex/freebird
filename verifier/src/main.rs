// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::Context;
use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    BatchVerifyReq, BatchVerifyResp, TokenToVerify, VerifyReq, VerifyResp, VerifyResult,
};
use freebird_common::logging;
use rayon::prelude::*;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use tracing::{debug, error, info, warn};

// Import from the library crate
use freebird_verifier::routes::admin::{self, AdminState, IssuerInfo, VerifierConfig};
use freebird_verifier::routes::admin_rate_limit::AdminRateLimiter;
use freebird_verifier::store::{SpendStore, StoreBackend};

#[derive(Clone)]
struct AppState {
    issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    store: Arc<dyn SpendStore>,
    /// Maximum acceptable clock skew in seconds (default: 300 = 5 minutes)
    max_clock_skew_secs: i64,
    /// Epoch configuration (kept for admin display / backward compat)
    epoch_duration_sec: u64,
    epoch_retention: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Clone, Debug, Deserialize)]
struct VoprfInfo {
    suite: String,
    kid: String,
    pubkey: String,
    exp_sec: u64,
}

// IssuerInfo is imported from freebird_verifier::routes::admin

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init("debug");

    // ---------- Configuration ----------
    let max_clock_skew_secs = std::env::var("MAX_CLOCK_SKEW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300); // Default: 5 minutes

    info!("Clock skew tolerance: {} seconds", max_clock_skew_secs);

    // ---------- Epoch Configuration ----------
    // Kept for admin config display; V3 tokens are self-contained and don't use epochs.
    let epoch_duration_sec = std::env::var("EPOCH_DURATION_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(86400); // Default: 1 day

    let epoch_retention = std::env::var("EPOCH_RETENTION")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2); // Default: accept 2 previous epochs

    // ---------- Backend selection ----------
    let (backend, store_backend_name) = if let Ok(url) = std::env::var("REDIS_URL") {
        (StoreBackend::Redis(url), "redis".to_string())
    } else {
        (StoreBackend::InMemory, "memory".to_string())
    };
    let store = backend.build().await;

    // ---------- Issuer metadata refresh ----------
    // Support multiple issuer URLs (comma-separated) with backward compatibility
    let issuer_urls: Vec<String> = std::env::var("ISSUER_URLS")
        .or_else(|_| std::env::var("ISSUER_URL")) // backward compat
        .unwrap_or_else(|_| "http://127.0.0.1:8081/.well-known/issuer".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    info!(
        "Configured {} issuer URL(s): {:?}",
        issuer_urls.len(),
        issuer_urls
    );

    let refresh_interval_min: u64 = std::env::var("REFRESH_INTERVAL_MIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // ---------- Admin API Configuration ----------
    let admin_api_key = std::env::var("ADMIN_API_KEY").ok();
    let behind_proxy = std::env::var("BEHIND_PROXY")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Server start time for uptime tracking
    let start_time = Instant::now();

    // Store issuer URLs for admin config
    let issuer_urls_for_admin = issuer_urls.clone();

    let issuers = Arc::new(RwLock::new(HashMap::new()));
    let state = Arc::new(AppState {
        issuers: Arc::clone(&issuers),
        store: Arc::clone(&store),
        max_clock_skew_secs,
        epoch_duration_sec,
        epoch_retention,
    });

    // Background refresh loop for all issuer URLs
    let refresh_state = Arc::clone(&state);
    tokio::spawn(async move {
        // Track failures per-URL for independent backoff
        let mut failures: HashMap<String, u32> = HashMap::new();
        loop {
            for url in &issuer_urls {
                match refresh_issuer_metadata(&refresh_state, url).await {
                    Ok(_) => {
                        failures.insert(url.clone(), 0);
                    }
                    Err(e) => {
                        let count = failures.entry(url.clone()).or_insert(0);
                        *count += 1;
                        warn!(?e, %url, failures = *count, "issuer refresh failed");
                    }
                }
            }
            // Use max failure count across all URLs for backoff calculation
            let max_failures = failures.values().copied().max().unwrap_or(0);
            let delay = refresh_interval_min
                .saturating_mul(60)
                .saturating_mul(u64::from((max_failures + 1).min(5)));

            sleep(Duration::from_secs(delay)).await;
        }
    });

    // ---------- Router ----------
    let mut app = Router::new()
        .route("/v1/verify", post(verify_with_logging))
        .route("/v1/verify/batch", post(batch_verify))
        .route("/v1/check", post(check_with_logging))
        .with_state(state);

    // ---------- Admin Router (optional) ----------
    if let Some(api_key) = admin_api_key {
        if api_key.len() >= 32 {
            let require_tls = std::env::var("REQUIRE_TLS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            let session_key = admin::derive_session_key(&api_key);
            let admin_state = Arc::new(AdminState {
                issuers: Arc::clone(&issuers),
                store: Arc::clone(&store),
                api_key,
                session_key,
                rate_limiter: AdminRateLimiter::new(),
                behind_proxy,
                require_tls,
                start_time,
                config: VerifierConfig {
                    max_clock_skew_secs,
                    epoch_duration_sec,
                    epoch_retention,
                    refresh_interval_min,
                    store_backend: store_backend_name,
                    issuer_urls: issuer_urls_for_admin,
                },
            });

            let admin_router = admin::admin_router(admin_state);
            app = app.nest("/admin", admin_router);
            info!("Admin API enabled at /admin");
        } else {
            warn!("ADMIN_API_KEY is too short (minimum 32 characters), admin API disabled");
        }
    } else {
        info!("Admin API disabled (no ADMIN_API_KEY set)");
    }

    // ---------- Serve ----------
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".into());
    let addr: SocketAddr = bind_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Freebird verifier listening on http://{}",
        listener.local_addr()?
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

// ---------- Background metadata refresh ----------
async fn refresh_issuer_metadata(state: &Arc<AppState>, issuer_url: &str) -> anyhow::Result<()> {
    info!(%issuer_url, "fetching issuer metadata");
    let res = reqwest::get(issuer_url)
        .await?
        .error_for_status()
        .context("issuer metadata request failed")?;
    let wk: WellKnown = res.json().await?;
    let pubkey_bytes =
        Base64UrlUnpadded::decode_vec(&wk.voprf.pubkey).context("base64 decode pubkey")?;

    let kid_for_log = wk.voprf.kid.clone();
    let ctx_len = b"freebird:v1".len();
    let info = IssuerInfo {
        pubkey_bytes,
        kid: wk.voprf.kid,
        ctx: b"freebird:v1".to_vec(),
        exp_sec: wk.voprf.exp_sec,
        last_refreshed: Some(Instant::now()),
    };

    let mut issuers = state.issuers.write().await;
    issuers.insert(wk.issuer_id.clone(), info);
    info!(issuer = %wk.issuer_id, kid = %kid_for_log, ctx_len, "updated issuer metadata");
    Ok(())
}

// ============================================================================
// V3 Token Verification Core
// ============================================================================

/// Parse a V3 redemption token from a base64url-encoded string, look up
/// the issuer, verify expiration, and verify the ECDSA signature.
///
/// Returns `(parsed_token, issuer_info)` on success.
fn verify_v3_token(
    token_b64: &str,
    issuers: &HashMap<String, IssuerInfo>,
    max_clock_skew_secs: i64,
) -> Result<(freebird_crypto::RedemptionToken, IssuerInfo), (StatusCode, String)> {
    // 1) Decode base64url to get raw bytes
    let token_bytes = Base64UrlUnpadded::decode_vec(token_b64).map_err(|e| {
        error!("Failed to decode token: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            "invalid token encoding".to_string(),
        )
    })?;

    // 2) Parse V3 redemption token
    let parsed = freebird_crypto::parse_redemption_token(&token_bytes).map_err(|e| {
        error!("Failed to parse V3 token: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            format!("invalid token format: {:?}", e),
        )
    })?;

    // 3) Check expiration (with clock skew tolerance)
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    if now > parsed.exp + max_clock_skew_secs {
        let expired_by = now - parsed.exp;
        warn!(
            "Token expired: expired_by={}s (tolerance={}s)",
            expired_by, max_clock_skew_secs
        );
        return Err((StatusCode::UNAUTHORIZED, "token expired".to_string()));
    }

    // 4) Look up issuer pubkey using (kid, issuer_id) from the token
    let issuer = issuers.get(&parsed.issuer_id).ok_or_else(|| {
        error!("Issuer not found: {}", parsed.issuer_id);
        (StatusCode::UNAUTHORIZED, "verification failed".to_string())
    })?;

    // Also check for tokens with expiration too far in the future
    if parsed.exp > now + issuer.exp_sec as i64 + max_clock_skew_secs {
        warn!(
            "Token expiration too far in future: exp={}, max_expected={}",
            parsed.exp,
            now + issuer.exp_sec as i64
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid token expiration".to_string(),
        ));
    }

    debug!(
        "Token not expired (exp in {}s), issuer={}, kid={}",
        parsed.exp - now,
        parsed.issuer_id,
        parsed.kid
    );

    // 5) Verify ECDSA signature over metadata
    let sig_valid = freebird_crypto::verify_token_signature(
        &issuer.pubkey_bytes,
        &parsed.sig,
        &parsed.kid,
        parsed.exp,
        &parsed.issuer_id,
    );

    if !sig_valid {
        error!("Signature verification failed - token metadata tampered or invalid");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".to_string()));
    }

    debug!("Signature verified - token metadata authentic");

    Ok((parsed, issuer.clone()))
}

// ============================================================================
// Verification handlers
// ============================================================================

// Wrapper to catch and log JSON deserialization errors
async fn verify_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("/v1/verify request received");

    match result {
        Ok(Json(req)) => {
            debug!("Full request: {:?}", req);
            verify(state, Json(req)).await
        }
        Err(rejection) => {
            error!("JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

// ---------- Verification handler (V3 self-contained tokens) ----------
async fn verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("Starting V3 token verification");

    // 1) Parse and verify the V3 token (expiration + ECDSA signature)
    let issuers = st.issuers.read().await;
    let (parsed, issuer) = verify_v3_token(&req.token_b64, &issuers, st.max_clock_skew_secs)?;
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // 2) Derive nullifier from unblinded PRF output
    let output_b64 = Base64UrlUnpadded::encode_string(&parsed.output);
    let null_key = freebird_crypto::nullifier_key(&parsed.issuer_id, &output_b64);
    let spend_key = format!("freebird:spent:{}:{}", parsed.issuer_id, null_key);
    debug!("Checking replay with key: {}", spend_key);

    // 3) Replay / spend tracking
    let spent = st
        .store
        .mark_spent(&spend_key, Duration::from_secs(issuer.exp_sec))
        .await
        .map_err(|e| {
            error!(%spend_key, "store error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".into())
        })?;

    if !spent {
        warn!(%spend_key, "replay detected (token already used)");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".into()));
    }

    // 4) Success
    info!(
        "Token verified successfully: issuer={}, kid={}, nullifier={}",
        parsed.issuer_id,
        parsed.kid,
        &null_key[..16]
    );

    Ok(Json(VerifyResp {
        ok: true,
        error: None,
        verified_at: now,
    }))
}

// ---------- Check handler (verify without consuming) ----------
// Wrapper to catch and log JSON deserialization errors
async fn check_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("/v1/check request received");

    match result {
        Ok(Json(req)) => {
            debug!("Full request: {:?}", req);
            check(state, Json(req)).await
        }
        Err(rejection) => {
            error!("JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

/// Check token validity WITHOUT consuming/recording the nullifier.
///
/// This endpoint validates the token's V3 format, expiration, and ECDSA
/// signature but does NOT mark it as spent. Use this for:
/// - Verifying a user holds a valid Day Pass
/// - Checking token validity before a multi-step operation
/// - Rate-limiting based on token possession without consumption
///
/// The token can still be used with /v1/verify after being checked here.
async fn check(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("Starting V3 token check (no consumption)");

    // Parse and verify the V3 token (expiration + ECDSA signature)
    let issuers = st.issuers.read().await;
    let (parsed, _issuer) = verify_v3_token(&req.token_b64, &issuers, st.max_clock_skew_secs)?;
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // NOTE: We intentionally skip mark_spent() here - this is the key difference from /v1/verify
    // The token remains valid for future use with /v1/verify

    info!(
        "Token check passed (not consumed): issuer={}, kid={}",
        parsed.issuer_id, parsed.kid
    );

    Ok(Json(VerifyResp {
        ok: true,
        error: None,
        verified_at: now,
    }))
}

/// Maximum batch size for batch verification
const MAX_BATCH_SIZE: usize = 10_000;

/// Minimum batch size for parallel processing
const MIN_PARALLEL_BATCH_SIZE: usize = 10;

fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

// ---------- Batch Verification Handler (V3) ----------
async fn batch_verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<BatchVerifyReq>,
) -> Result<Json<BatchVerifyResp>, (StatusCode, String)> {
    let start = Instant::now();
    let batch_size = req.tokens.len();

    info!("/v1/verify/batch: size={}", batch_size);

    // --- VALIDATION ---
    if batch_size == 0 {
        return Err((StatusCode::BAD_REQUEST, "batch cannot be empty".to_string()));
    }

    if batch_size > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "batch size {} exceeds maximum {}",
                batch_size, MAX_BATCH_SIZE
            ),
        ));
    }

    // Snapshot issuers map for parallel processing
    let issuers = st.issuers.read().await;
    let issuers_snapshot: HashMap<String, IssuerInfo> = issuers.clone();
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let runtime_handle = tokio::runtime::Handle::current();
    let max_clock_skew = st.max_clock_skew_secs;

    // Helper function to verify a single V3 token
    let verify_one = |token_req: &TokenToVerify| -> VerifyResult {
        // 1) Parse and verify the V3 token
        let (parsed, issuer) = match verify_v3_token(
            &token_req.token_b64,
            &issuers_snapshot,
            max_clock_skew,
        ) {
            Ok(r) => r,
            Err((_status, msg)) => {
                return VerifyResult::Error {
                    message: msg,
                    code: "verification_failed".to_string(),
                };
            }
        };

        // 2) Derive nullifier from unblinded PRF output
        let output_b64 = Base64UrlUnpadded::encode_string(&parsed.output);
        let null_key = freebird_crypto::nullifier_key(&parsed.issuer_id, &output_b64);
        let spend_key = format!("freebird:spent:{}:{}", parsed.issuer_id, null_key);

        // 3) Check for replay
        // Use captured runtime handle to bridge rayon and tokio.
        let spent = runtime_handle.block_on(async {
            st.store
                .mark_spent(&spend_key, Duration::from_secs(issuer.exp_sec))
                .await
        });

        match spent {
            Ok(true) => VerifyResult::Success { verified_at: now },
            Ok(false) => VerifyResult::Error {
                message: "token already used".to_string(),
                code: "replay_detected".to_string(),
            },
            Err(_) => VerifyResult::Error {
                message: "store error".to_string(),
                code: "store_error".to_string(),
            },
        }
    };

    // Process tokens in parallel or sequentially based on batch size
    let results: Vec<VerifyResult> = if batch_size < MIN_PARALLEL_BATCH_SIZE {
        debug!(
            "using sequential processing for small batch (n={})",
            batch_size
        );
        req.tokens.iter().map(verify_one).collect()
    } else {
        debug!("using parallel processing for batch (n={})", batch_size);
        req.tokens.par_iter().map(verify_one).collect()
    };

    // --- AGGREGATE RESULTS ---
    let successful = results
        .iter()
        .filter(|r| matches!(r, VerifyResult::Success { .. }))
        .count();
    let failed = batch_size - successful;

    let total_time_ms = start.elapsed().as_millis() as u64;
    let throughput = compute_throughput(successful, total_time_ms);

    info!(
        "Batch verify metrics: total={}ms, success={}/{}, throughput={:.0} tok/s",
        total_time_ms, successful, batch_size, throughput
    );

    Ok(Json(BatchVerifyResp {
        results,
        successful,
        failed,
        processing_time_ms: total_time_ms,
        throughput,
    }))
}

// ---------- Graceful shutdown ----------
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::compute_throughput;

    #[test]
    fn test_compute_throughput_zero_time() {
        assert_eq!(compute_throughput(100, 0), 0.0);
    }

    #[test]
    fn test_compute_throughput_normal() {
        assert_eq!(compute_throughput(500, 250), 2000.0);
    }
}
