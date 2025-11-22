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
use common::logging;
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use tracing::{debug, error, info, warn};
use common::api::{VerifyReq, VerifyResp};

// FIX: Import from the library crate instead of local mod
use verifier::store::{SpendStore, StoreBackend};

#[derive(Clone)]
struct AppState {
    issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    store: Arc<dyn SpendStore>,
    /// Maximum acceptable clock skew in seconds (default: 300 = 5 minutes)
    max_clock_skew_secs: i64,
    /// MAC key for token metadata verification (derived from issuer secret)
    mac_key: [u8; 32],
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

#[derive(Clone)]
struct IssuerInfo {
    pubkey_bytes: Vec<u8>,
    kid: String,
    ctx: Vec<u8>,
    exp_sec: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init("debug");

    // ---------- Configuration ----------
    let max_clock_skew_secs = std::env::var("MAX_CLOCK_SKEW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300); // Default: 5 minutes

    info!("⏰ Clock skew tolerance: {} seconds", max_clock_skew_secs);

    // ---------- MAC Key Configuration ----------
    // The verifier needs the issuer's secret key to derive the MAC key
    // In production deployments, issuer and verifier are managed by the same entity
    let issuer_secret = std::env::var("ISSUER_SECRET_KEY")
        .context("ISSUER_SECRET_KEY environment variable not set")?;

    // Decode hex secret key
    let sk_bytes: [u8; 32] = hex::decode(&issuer_secret)
        .context("Invalid ISSUER_SECRET_KEY hex encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ISSUER_SECRET_KEY must be exactly 32 bytes (64 hex chars)"))?;

    // Derive MAC key (using legacy version for now - will upgrade to v2)
    let mac_key = crypto::derive_mac_key(&sk_bytes, b"freebird:mac:v1");

    info!("🔐 MAC key derived for token metadata verification");

    // ---------- Backend selection ----------
    let backend = if let Ok(url) = std::env::var("REDIS_URL") {
        StoreBackend::Redis(url)
    } else {
        StoreBackend::InMemory
    };
    let store = backend.build().await;

    // ---------- Issuer metadata refresh ----------
    let issuer_url = std::env::var("ISSUER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081/.well-known/issuer".into());
    let refresh_interval_min: u64 = std::env::var("REFRESH_INTERVAL_MIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let state = Arc::new(AppState {
        issuers: Arc::new(RwLock::new(HashMap::new())),
        store,
        max_clock_skew_secs,
        mac_key,
    });

    // Background refresh loop
    let refresh_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut failures = 0u32;
        loop {
            match refresh_issuer_metadata(&refresh_state, &issuer_url).await {
                Ok(_) => failures = 0,
                Err(e) => {
                    failures += 1;
                    warn!(?e, failures, "issuer refresh failed");
                }
            }
            let delay = refresh_interval_min
                .saturating_mul(60)
                .saturating_mul(u64::from((failures + 1).min(5)));

            sleep(Duration::from_secs(delay)).await;
        }
    });

    // ---------- Router ----------
    let app = Router::new()
        .route("/v1/verify", post(verify_with_logging))
        .with_state(state);

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

    // 3) Verify MAC over token metadata (constant-time)
    //    This must happen BEFORE VOPRF verification to prevent tampering
    let exp_value = req.exp.ok_or_else(|| {
        error!("❌ Token missing expiration field");
        (StatusCode::BAD_REQUEST, "token must include expiration".to_string())
    })?;

    // Decode token to split MAC from token data
    let token_with_mac = Base64UrlUnpadded::decode_vec(&req.token_b64).map_err(|e| {
        error!("❌ Failed to decode token: {:?}", e);
        (StatusCode::BAD_REQUEST, "invalid token encoding".to_string())
    })?;

    // Token format: [VERSION||A||B||Proof||MAC]
    // Expected: 131 bytes (VOPRF) + 32 bytes (MAC) = 163 bytes
    if token_with_mac.len() != 163 {
        error!("❌ Invalid token length: got {} bytes, expected 163", token_with_mac.len());
        return Err((StatusCode::BAD_REQUEST, "invalid token length".to_string()));
    }

    // Split token and MAC
    let (token_data, mac_bytes) = token_with_mac.split_at(131);
    let received_mac: [u8; 32] = mac_bytes.try_into().expect("MAC is 32 bytes");

    // Verify MAC in constant time
    let mac_valid = crypto::verify_token_mac(
        &st.mac_key,
        token_data,
        &received_mac,
        &issuer.kid,
        exp_value,
        &req.issuer_id,
    );

    if !mac_valid {
        error!("❌ MAC verification failed - token metadata tampered");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".to_string()));
    }

    debug!("✅ MAC verified - token metadata authentic");

    // 4) Verify DLEQ token and derive PRF output (without MAC)
    debug!("Verifying DLEQ token with context len={}", issuer.ctx.len());
    let verifier = crypto::Verifier::new(&issuer.ctx);

    // Pass only the token data (without MAC) to VOPRF verifier
    let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
    let out_b64 = verifier
        .verify(&token_data_b64, &issuer.pubkey_bytes)
        .map_err(|e| {
            error!("Token cryptographic verification failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, "verification failed".into())
        })?;

    debug!("✅ Token cryptographically valid, PRF output derived");

    // 4) Replay / spend tracking
    let null_key = crypto::nullifier_key(&req.issuer_id, &out_b64);
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

    // 5) Success
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
