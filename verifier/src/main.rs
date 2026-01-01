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
use freebird_common::logging;
use rayon::prelude::*;
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use tracing::{debug, error, info, warn};
use freebird_common::api::{VerifyReq, VerifyResp, BatchVerifyReq, BatchVerifyResp, VerifyResult, TokenToVerify};

// Import from the library crate
use freebird_verifier::store::{SpendStore, StoreBackend};
use freebird_verifier::routes::admin::{self, AdminState, VerifierConfig, IssuerInfo};
use freebird_verifier::routes::admin_rate_limit::AdminRateLimiter;

#[derive(Clone)]
struct AppState {
    issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    store: Arc<dyn SpendStore>,
    /// Maximum acceptable clock skew in seconds (default: 300 = 5 minutes)
    max_clock_skew_secs: i64,
    /// Epoch configuration
    epoch_duration_sec: u64,
    epoch_retention: u32,
}

impl AppState {
    /// Calculate current epoch based on Unix timestamp
    fn current_epoch(&self) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now / self.epoch_duration_sec) as u32
    }

    /// Check if an epoch is valid (within acceptable range)
    fn is_epoch_valid(&self, epoch: u32) -> bool {
        let current = self.current_epoch();
        let min_valid = current.saturating_sub(self.epoch_retention);
        epoch >= min_valid && epoch <= current
    }
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

    info!("⏰ Clock skew tolerance: {} seconds", max_clock_skew_secs);

    // ---------- Epoch Configuration ----------
    // Verifier uses signature-based authentication (no secret key required)
    let epoch_duration_sec = std::env::var("EPOCH_DURATION_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(86400); // Default: 1 day

    let epoch_retention = std::env::var("EPOCH_RETENTION")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2); // Default: accept 2 previous epochs

    info!("🔐 Epoch configuration: duration={}s, retention={}", epoch_duration_sec, epoch_retention);

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

    info!("📡 Configured {} issuer URL(s): {:?}", issuer_urls.len(), issuer_urls);

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
            let admin_state = Arc::new(AdminState {
                issuers: Arc::clone(&issuers),
                store: Arc::clone(&store),
                api_key,
                rate_limiter: AdminRateLimiter::new(),
                behind_proxy,
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
            info!("🔐 Admin API enabled at /admin");
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
        "🕊️ Freebird verifier listening on http://{}",
        listener.local_addr()?
    );

    axum::serve(listener, app)
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

// Wrapper to catch and log JSON deserialization errors
async fn verify_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("📥 /v1/verify request received");

    match result {
        Ok(Json(req)) => {
            info!("✅ Request parsed: issuer_id={}", req.issuer_id);
            debug!("Full request: {:?}", req);
            verify(state, Json(req)).await
        }
        Err(rejection) => {
            error!("❌ JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

// ---------- Verification handler with expiration checking ----------
async fn verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("🔍 Starting verification for issuer={}", req.issuer_id);

    // 1) Lookup issuer
    let issuers = st.issuers.read().await;
    debug!("Loaded issuers map, contains {} entries", issuers.len());

    let issuer = issuers.get(&req.issuer_id).ok_or_else(|| {
        error!("Issuer not found: {}", req.issuer_id);
        (StatusCode::UNAUTHORIZED, "verification failed".to_string())
    })?;

    debug!("Found issuer: kid={}", issuer.kid);

    // 2) NEW: Check token expiration BEFORE cryptographic verification
    //    This prevents wasting CPU on expired tokens
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // Determine expiration time:
    // - Use explicit exp from request if provided
    // - Otherwise, tokens expire based on issuer's default TTL from issuance time
    // Note: For proper validation, tokens should include their exp in the request
    if let Some(exp) = req.exp {
        debug!("Checking explicit expiration: exp={}, now={}", exp, now);

        // Check if token has expired (with clock skew tolerance)
        if now > exp + st.max_clock_skew_secs {
            let expired_by = now - exp;
            warn!(
                "❌ Token expired: expired_by={}s (tolerance={}s)",
                expired_by, st.max_clock_skew_secs
            );
            return Err((StatusCode::UNAUTHORIZED, "token expired".to_string()));
        }

        // Also check for tokens with expiration too far in the future
        // (possible clock skew or forged timestamps)
        let max_future_time = now + st.max_clock_skew_secs;
        if exp > now + issuer.exp_sec as i64 + st.max_clock_skew_secs {
            warn!(
                "❌ Token expiration too far in future: exp={}, max_expected={}",
                exp,
                now + issuer.exp_sec as i64
            );
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid token expiration".to_string(),
            ));
        }

        debug!("✅ Token not expired (exp in {}s)", exp - now);
    } else {
        debug!("⚠️ No explicit expiration provided, relying on nullifier TTL");
        // Without explicit exp, we rely on the nullifier TTL to prevent
        // old tokens from being used. This is less secure than explicit
        // expiration checking but maintains backward compatibility.
    }

    // 3) Validate epoch is within acceptable range
    if !st.is_epoch_valid(req.epoch) {
        error!(
            "❌ Invalid epoch: got {}, current={}, min_valid={}",
            req.epoch,
            st.current_epoch(),
            st.current_epoch().saturating_sub(st.epoch_retention)
        );
        return Err((StatusCode::BAD_REQUEST, "invalid epoch".to_string()));
    }

    debug!("✅ Epoch {} is valid", req.epoch);

    // 4) Authenticate token metadata using ECDSA signature
    let exp_value = req.exp.ok_or_else(|| {
        error!("❌ Token missing expiration field");
        (StatusCode::BAD_REQUEST, "token must include expiration".to_string())
    })?;

    // Decode token (195 bytes = 131 VOPRF + 64 ECDSA signature)
    let token_with_sig = Base64UrlUnpadded::decode_vec(&req.token_b64).map_err(|e| {
        error!("❌ Failed to decode token: {:?}", e);
        (StatusCode::BAD_REQUEST, "invalid token encoding".to_string())
    })?;

    // Validate token length (must be exactly 195 bytes)
    if token_with_sig.len() != 195 {
        error!("❌ Invalid token length: got {} bytes, expected 195", token_with_sig.len());
        return Err((StatusCode::BAD_REQUEST, "invalid token length (expected 195 bytes)".to_string()));
    }

    // Split token and signature
    let (token_data, sig_bytes) = token_with_sig.split_at(131);
    let received_signature: [u8; 64] = sig_bytes.try_into().expect("Signature is 64 bytes");

    // Verify signature using issuer's public key (federation mode!)
    let sig_valid = freebird_crypto::verify_token_signature(
        &issuer.pubkey_bytes,
        token_data,
        &received_signature,
        &issuer.kid,
        exp_value,
        &req.issuer_id,
    );

    if !sig_valid {
        error!("❌ Signature verification failed - token metadata tampered or invalid");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".to_string()));
    }

    debug!("✅ Signature verified - token metadata authentic");

    // 5) Verify DLEQ token and derive PRF output
    debug!("Verifying DLEQ token with context len={}", issuer.ctx.len());
    let verifier = freebird_crypto::Verifier::new(&issuer.ctx);

    // Pass only the token data (without authentication) to VOPRF verifier
    let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
    let out_b64 = verifier
        .verify(&token_data_b64, &issuer.pubkey_bytes)
        .map_err(|e| {
            error!("Token cryptographic verification failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, "verification failed".into())
        })?;

    debug!("✅ Token cryptographically valid, PRF output derived");

    // 4) Replay / spend tracking
    let null_key = freebird_crypto::nullifier_key(&req.issuer_id, &out_b64);
    let spend_key = format!("freebird:spent:{}:{}", req.issuer_id, null_key);
    debug!("Checking replay with key: {}", spend_key);

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

    // 6) Success
    info!(
        "✅ Token verified successfully: issuer={}, kid={}, nullifier={}",
        req.issuer_id,
        issuer.kid,
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
    info!("📥 /v1/check request received");

    match result {
        Ok(Json(req)) => {
            info!("✅ Request parsed: issuer_id={}", req.issuer_id);
            debug!("Full request: {:?}", req);
            check(state, Json(req)).await
        }
        Err(rejection) => {
            error!("❌ JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

/// Check token validity WITHOUT consuming/recording the nullifier.
///
/// This endpoint validates the token's cryptographic proof and expiration
/// but does NOT mark it as spent. Use this for:
/// - Verifying a user holds a valid Day Pass
/// - Checking token validity before a multi-step operation
/// - Rate-limiting based on token possession without consumption
///
/// The token can still be used with /v1/verify after being checked here.
async fn check(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("🔍 Starting check (no consumption) for issuer={}", req.issuer_id);

    // 1) Lookup issuer
    let issuers = st.issuers.read().await;
    debug!("Loaded issuers map, contains {} entries", issuers.len());

    let issuer = issuers.get(&req.issuer_id).ok_or_else(|| {
        error!("Issuer not found: {}", req.issuer_id);
        (StatusCode::UNAUTHORIZED, "check failed".to_string())
    })?;

    debug!("Found issuer: kid={}", issuer.kid);

    // 2) Check token expiration
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    if let Some(exp) = req.exp {
        debug!("Checking explicit expiration: exp={}, now={}", exp, now);

        // Check if token has expired (with clock skew tolerance)
        if now > exp + st.max_clock_skew_secs {
            let expired_by = now - exp;
            warn!(
                "❌ Token expired: expired_by={}s (tolerance={}s)",
                expired_by, st.max_clock_skew_secs
            );
            return Err((StatusCode::UNAUTHORIZED, "token expired".to_string()));
        }

        // Also check for tokens with expiration too far in the future
        if exp > now + issuer.exp_sec as i64 + st.max_clock_skew_secs {
            warn!(
                "❌ Token expiration too far in future: exp={}, max_expected={}",
                exp,
                now + issuer.exp_sec as i64
            );
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid token expiration".to_string(),
            ));
        }

        debug!("✅ Token not expired (exp in {}s)", exp - now);
    } else {
        debug!("⚠️ No explicit expiration provided");
    }

    // 3) Validate epoch is within acceptable range
    if !st.is_epoch_valid(req.epoch) {
        error!(
            "❌ Invalid epoch: got {}, current={}, min_valid={}",
            req.epoch,
            st.current_epoch(),
            st.current_epoch().saturating_sub(st.epoch_retention)
        );
        return Err((StatusCode::BAD_REQUEST, "invalid epoch".to_string()));
    }

    debug!("✅ Epoch {} is valid", req.epoch);

    // 4) Authenticate token metadata using ECDSA signature
    let exp_value = req.exp.ok_or_else(|| {
        error!("❌ Token missing expiration field");
        (StatusCode::BAD_REQUEST, "token must include expiration".to_string())
    })?;

    // Decode token (195 bytes = 131 VOPRF + 64 ECDSA signature)
    let token_with_sig = Base64UrlUnpadded::decode_vec(&req.token_b64).map_err(|e| {
        error!("❌ Failed to decode token: {:?}", e);
        (StatusCode::BAD_REQUEST, "invalid token encoding".to_string())
    })?;

    // Validate token length (must be exactly 195 bytes)
    if token_with_sig.len() != 195 {
        error!("❌ Invalid token length: got {} bytes, expected 195", token_with_sig.len());
        return Err((StatusCode::BAD_REQUEST, "invalid token length (expected 195 bytes)".to_string()));
    }

    // Split token and signature
    let (token_data, sig_bytes) = token_with_sig.split_at(131);
    let received_signature: [u8; 64] = sig_bytes.try_into().expect("Signature is 64 bytes");

    // Verify signature using issuer's public key
    let sig_valid = freebird_crypto::verify_token_signature(
        &issuer.pubkey_bytes,
        token_data,
        &received_signature,
        &issuer.kid,
        exp_value,
        &req.issuer_id,
    );

    if !sig_valid {
        error!("❌ Signature verification failed - token metadata tampered or invalid");
        return Err((StatusCode::UNAUTHORIZED, "check failed".to_string()));
    }

    debug!("✅ Signature verified - token metadata authentic");

    // 5) Verify DLEQ token (cryptographic proof)
    debug!("Verifying DLEQ token with context len={}", issuer.ctx.len());
    let verifier = freebird_crypto::Verifier::new(&issuer.ctx);

    let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
    let _out_b64 = verifier
        .verify(&token_data_b64, &issuer.pubkey_bytes)
        .map_err(|e| {
            error!("Token cryptographic verification failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, "check failed".into())
        })?;

    debug!("✅ Token cryptographically valid");

    // NOTE: We intentionally skip mark_spent() here - this is the key difference from /v1/verify
    // The token remains valid for future use with /v1/verify

    info!(
        "✅ Token check passed (not consumed): issuer={}, kid={}",
        req.issuer_id,
        issuer.kid
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

// ---------- Batch Verification Handler ----------
async fn batch_verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<BatchVerifyReq>,
) -> Result<Json<BatchVerifyResp>, (StatusCode, String)> {
    let start = Instant::now();
    let batch_size = req.tokens.len();

    info!(
        "🔥 /v1/verify/batch: size={}, issuer={}",
        batch_size, req.issuer_id
    );

    // --- VALIDATION ---
    if batch_size == 0 {
        return Err((StatusCode::BAD_REQUEST, "batch cannot be empty".to_string()));
    }

    if batch_size > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("batch size {} exceeds maximum {}", batch_size, MAX_BATCH_SIZE),
        ));
    }

    // --- LOOKUP ISSUER (once for all tokens) ---
    let issuers = st.issuers.read().await;
    let issuer = issuers.get(&req.issuer_id).ok_or_else(|| {
        error!("Issuer not found: {}", req.issuer_id);
        (StatusCode::UNAUTHORIZED, "verification failed".to_string())
    })?;

    // Clone issuer data so we can drop the lock before parallel processing
    let issuer_clone = issuer.clone();
    let issuer_id = req.issuer_id.clone();
    drop(issuers);

    info!("✅ Issuer found: kid={}", issuer_clone.kid);

    // --- PARALLEL VERIFICATION ---
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // Helper function to verify a single token
    let verify_one = |token_req: &TokenToVerify| -> VerifyResult {
        // 1) Validate epoch is within acceptable range
        if !st.is_epoch_valid(token_req.epoch) {
            return VerifyResult::Error {
                message: format!("invalid epoch: {}", token_req.epoch),
                code: "invalid_epoch".to_string(),
            };
        }

        // 2) Check expiration
        if let Some(exp) = token_req.exp {
            if now > exp + st.max_clock_skew_secs {
                return VerifyResult::Error {
                    message: "token expired".to_string(),
                    code: "expired".to_string(),
                };
            }

            if exp > now + issuer_clone.exp_sec as i64 + st.max_clock_skew_secs {
                return VerifyResult::Error {
                    message: "invalid token expiration".to_string(),
                    code: "invalid_expiration".to_string(),
                };
            }
        } else {
            return VerifyResult::Error {
                message: "token must include expiration".to_string(),
                code: "missing_expiration".to_string(),
            };
        }

        let exp_value = token_req.exp.unwrap();

        // 3) Decode token (must be 195 bytes = 131 VOPRF + 64 ECDSA signature)
        let token_with_sig = match Base64UrlUnpadded::decode_vec(&token_req.token_b64) {
            Ok(t) => t,
            Err(_) => {
                return VerifyResult::Error {
                    message: "invalid token encoding".to_string(),
                    code: "invalid_encoding".to_string(),
                };
            }
        };

        // Validate token length (must be exactly 195 bytes)
        if token_with_sig.len() != 195 {
            return VerifyResult::Error {
                message: format!("invalid token length: got {} bytes, expected 195", token_with_sig.len()),
                code: "invalid_length".to_string(),
            };
        }

        // Split token and signature
        let (token_data, sig_bytes) = token_with_sig.split_at(131);
        let received_signature: [u8; 64] = match sig_bytes.try_into() {
            Ok(s) => s,
            Err(_) => {
                return VerifyResult::Error {
                    message: "invalid signature".to_string(),
                    code: "invalid_signature".to_string(),
                };
            }
        };

        // Verify signature using issuer's public key
        let sig_valid = freebird_crypto::verify_token_signature(
            &issuer_clone.pubkey_bytes,
            token_data,
            &received_signature,
            &issuer_clone.kid,
            exp_value,
            &issuer_id,
        );

        if !sig_valid {
            return VerifyResult::Error {
                message: "signature verification failed".to_string(),
                code: "signature_verification_failed".to_string(),
            };
        }

        // 4) Verify VOPRF token
        let verifier = freebird_crypto::Verifier::new(&issuer_clone.ctx);
        let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
        let out_b64 = match verifier.verify(&token_data_b64, &issuer_clone.pubkey_bytes) {
            Ok(o) => o,
            Err(_) => {
                return VerifyResult::Error {
                    message: "cryptographic verification failed".to_string(),
                    code: "voprf_verification_failed".to_string(),
                };
            }
        };

        // 5) Check for replay - this is the only part that needs to be async
        // We'll handle this synchronously in the parallel loop by using block_on
        let null_key = freebird_crypto::nullifier_key(&issuer_id, &out_b64);
        let spend_key = format!("freebird:spent:{}:{}", issuer_id, null_key);

        // Use tokio::runtime::Handle to bridge rayon and tokio
        let handle = tokio::runtime::Handle::current();
        let spent = handle.block_on(async {
            st.store
                .mark_spent(&spend_key, Duration::from_secs(issuer_clone.exp_sec))
                .await
        });

        match spent {
            Ok(true) => VerifyResult::Success {
                verified_at: now,
            },
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
        debug!("using sequential processing for small batch (n={})", batch_size);
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
    let throughput = (successful as f64 / total_time_ms as f64) * 1000.0;

    info!(
        "📊 Batch verify metrics: total={}ms, success={}/{}, throughput={:.0} tok/s",
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
