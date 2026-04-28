// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{anyhow, Context};
use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    BatchVerifyReq, BatchVerifyResp, KeyDiscoveryResp, PublicKeyInfo, TokenToVerify,
    VerifierMetadataResp, VerifyReq, VerifyResp, VerifyResult,
};
use freebird_common::logging;
use freebird_common::metrics::{self, MetricsMiddleware};
use rayon::prelude::*;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, instrument, warn};

/// Convert a handler panic into a structured JSON 500 so that internal
/// details (stack traces, key material) are never forwarded to clients.
fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let msg = if let Some(s) = err.downcast_ref::<&'static str>() {
        *s
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.as_str()
    } else {
        "unknown panic"
    };

    tracing::error!(panic.message = %msg, "handler panic caught; suppressing details from client");

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": "internal_error",
            "code": "INTERNAL_ERROR"
        })),
    )
        .into_response()
}

// Import from the library crate
use freebird_verifier::routes::admin::{self, AdminState, IssuerInfo, VerifierConfig};
use freebird_verifier::routes::admin_rate_limit::AdminRateLimiter;
use freebird_verifier::store::{SpendStore, StoreBackend};
use freebird_verifier::verify::{decode_token_version, verify_v4_token, verify_v5_public_token};

#[derive(Clone)]
struct AppState {
    issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    store: Arc<dyn SpendStore>,
    verifier_id: String,
    audience: String,
    scope_digest: [u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    /// Epoch configuration kept for admin display / operator observability.
    /// V4 token lifetime is controlled by verifier key acceptance policy,
    /// but operators still configure these env vars and expect them surfaced.
    #[allow(dead_code)]
    epoch_duration_sec: u64,
    #[allow(dead_code)]
    epoch_retention: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Clone, Debug, Deserialize)]
struct VoprfInfo {
    /// VOPRF suite identifier from the issuer well-known JSON (e.g. "P256-SHA256").
    /// Deserialized for completeness; the V4 verifier does not branch on suite name.
    #[allow(dead_code)]
    suite: String,
    kid: String,
    pubkey: String,
}

// IssuerInfo is imported from freebird_verifier::routes::admin

fn decode_secret_key_b64(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = Base64UrlUnpadded::decode_vec(value.trim()).context("base64 decode secret key")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("secret key must decode to exactly 32 bytes"))
}

fn read_secret_key_file(path: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("read secret key file {path}"))?;
    if bytes.len() == 32 {
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("32-byte secret key copy failed"));
    }

    let text = std::str::from_utf8(&bytes)
        .context("secret key file must be raw 32 bytes or base64url text")?;
    decode_secret_key_b64(text)
}

fn load_default_verification_key() -> anyhow::Result<Option<[u8; 32]>> {
    if let Ok(value) = std::env::var("VERIFIER_SK_B64") {
        return decode_secret_key_b64(&value).map(Some);
    }

    let path = std::env::var("VERIFIER_SK_PATH")
        .or_else(|_| std::env::var("ISSUER_SK_PATH"))
        .ok();
    match path {
        Some(path) => read_secret_key_file(&path).map(Some),
        None => Ok(None),
    }
}

fn load_verification_keyring() -> anyhow::Result<HashMap<String, [u8; 32]>> {
    let Some(raw) = std::env::var("VERIFIER_KEYRING_B64").ok() else {
        return Ok(HashMap::new());
    };

    let encoded: HashMap<String, String> =
        serde_json::from_str(&raw).context("parse VERIFIER_KEYRING_B64 JSON")?;
    encoded
        .into_iter()
        .map(|(kid, key_b64)| decode_secret_key_b64(&key_b64).map(|key| (kid, key)))
        .collect()
}

fn issuer_keys_url(issuer_url: &str) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(issuer_url).context("parse issuer metadata URL")?;
    url.set_path("/.well-known/keys");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

async fn load_public_keys(
    issuer_url: &str,
    issuer_id: &str,
) -> anyhow::Result<
    HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], admin::PublicIssuerKey>,
> {
    let keys_url = issuer_keys_url(issuer_url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;
    let url = reqwest::Url::parse(&keys_url).context("parse keys URL")?;
    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("issuer key discovery request failed: {keys_url}"))?;
    let discovery: KeyDiscoveryResp = res.json().await?;
    if discovery.issuer_id != issuer_id {
        return Err(anyhow!(
            "issuer key discovery returned issuer_id {}, expected {}",
            discovery.issuer_id,
            issuer_id
        ));
    }

    let mut keys = HashMap::new();
    for key_info in discovery.public {
        match parse_public_key_info(issuer_id, key_info) {
            Ok(key) => {
                keys.insert(key.token_key_id, key);
            }
            Err(e) => warn!(?e, issuer = %issuer_id, "dropping invalid V5 public bearer key"),
        }
    }
    Ok(keys)
}

fn parse_public_key_info(
    issuer_id: &str,
    key_info: PublicKeyInfo,
) -> anyhow::Result<admin::PublicIssuerKey> {
    if key_info.issuer_id != issuer_id {
        return Err(anyhow!("public key issuer_id mismatch"));
    }
    if key_info.token_type != freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE {
        return Err(anyhow!("unsupported public token type"));
    }
    if key_info.rfc9474_variant != freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT {
        return Err(anyhow!("unsupported RFC 9474 variant"));
    }
    if key_info.spend_policy != freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE {
        return Err(anyhow!("unsupported public bearer spend_policy"));
    }
    if matches!(key_info.max_uses, Some(max_uses) if max_uses != 1) {
        return Err(anyhow!("unsupported public bearer max_uses"));
    }
    if !(2048..=4096).contains(&key_info.modulus_bits) {
        return Err(anyhow!("unsupported public bearer modulus_bits"));
    }
    if key_info.valid_from >= key_info.valid_until {
        return Err(anyhow!("invalid public bearer validity window"));
    }

    let token_key_id = freebird_crypto::decode_token_key_id_hex(&key_info.token_key_id)
        .map_err(|_| anyhow!("invalid token_key_id"))?;
    let pubkey_spki = Base64UrlUnpadded::decode_vec(&key_info.pubkey_spki_b64)
        .context("base64 decode public bearer SPKI")?;
    freebird_crypto::validate_public_bearer_spki(&pubkey_spki)
        .map_err(|e| anyhow!("invalid public bearer SPKI: {:?}", e))?;
    if freebird_crypto::token_key_id_from_spki(&pubkey_spki) != token_key_id {
        return Err(anyhow!("token_key_id does not match SPKI"));
    }

    Ok(admin::PublicIssuerKey {
        token_key_id,
        token_key_id_hex: key_info.token_key_id,
        pubkey_spki,
        issuer_id: key_info.issuer_id,
        valid_from: key_info.valid_from,
        valid_until: key_info.valid_until,
        audience: key_info.audience,
    })
}

fn validate_secret_key_matches_pubkey(
    secret_key: [u8; 32],
    ctx: &[u8],
    pubkey_bytes: &[u8],
) -> anyhow::Result<()> {
    let server = freebird_crypto::Server::from_secret_key(secret_key, ctx)
        .map_err(|e| anyhow!("invalid verifier secret key: {:?}", e))?;
    let derived = server.public_key_sec1_compressed();
    if derived.as_slice() != pubkey_bytes {
        return Err(anyhow!(
            "verifier secret key does not match issuer metadata public key"
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init("debug");
    metrics::register_metrics();

    // ---------- Configuration ----------
    // ---------- Epoch Configuration ----------
    // Kept for admin config display; V4 tokens rely on key acceptance windows.
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
    let store = backend.build().await?;

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

    let verifier_id = std::env::var("VERIFIER_ID")
        .context("VERIFIER_ID is required so V4 tokens are bound to a verifier scope")?;
    let audience = std::env::var("VERIFIER_AUDIENCE").unwrap_or_else(|_| verifier_id.clone());
    let scope_digest = freebird_crypto::build_scope_digest(&verifier_id, &audience)
        .map_err(|e| anyhow!("invalid verifier scope: {:?}", e))?;
    info!(
        verifier_id = %verifier_id,
        audience = %audience,
        "Configured verifier scope"
    );

    // ---------- Admin API Configuration ----------
    let admin_api_key = match std::env::var("ADMIN_API_KEY") {
        Ok(key) if key.len() >= 32 => key,
        Ok(key) => anyhow::bail!(
            "ADMIN_API_KEY must be at least 32 characters, got {}",
            key.len()
        ),
        Err(_) => anyhow::bail!("ADMIN_API_KEY must be set (minimum 32 characters)"),
    };
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
        verifier_id: verifier_id.clone(),
        audience: audience.clone(),
        scope_digest,
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
        .route("/health", get(health_handler))
        .route("/.well-known/verifier", get(verifier_metadata))
        .route("/v1/verify", post(verify_with_logging))
        .route("/v1/verify/batch", post(batch_verify))
        .route("/v1/check", post(check_with_logging))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([axum::http::header::CONTENT_TYPE])
                .max_age(Duration::from_secs(86400)),
        )
        .layer(freebird_common::rate_limit::PublicRateLimitLayer::default())
        .with_state(state);

    let require_tls = std::env::var("REQUIRE_TLS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let session_key = admin::derive_session_key(&admin_api_key);
    let admin_state = Arc::new(AdminState {
        issuers: Arc::clone(&issuers),
        store: Arc::clone(&store),
        api_key: admin_api_key,
        session_key,
        rate_limiter: AdminRateLimiter::new(),
        behind_proxy,
        require_tls,
        start_time,
        config: VerifierConfig {
            epoch_duration_sec,
            epoch_retention,
            refresh_interval_min,
            store_backend: store_backend_name,
            issuer_urls: issuer_urls_for_admin,
            verifier_id: verifier_id.clone(),
            audience: audience.clone(),
        },
    });

    let rate_limiter_clone = Arc::clone(&admin_state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            rate_limiter_clone.rate_limiter.cleanup_expired().await;
        }
    });

    let admin_router = admin::admin_router(admin_state);
    app = app.nest("/admin", admin_router);
    info!("Admin API enabled at /admin");

    // Outermost layers: catch panics before they escape handlers, then emit
    // HTTP tracing spans for every inbound request.
    let app = app.layer(
        ServiceBuilder::new()
            .layer(CatchPanicLayer::custom(handle_panic))
            .layer(TraceLayer::new_for_http())
            .layer(MetricsMiddleware)
            .layer(freebird_common::tls_enforcement::TlsEnforcementLayer::new()),
    );

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
#[instrument(skip(state), fields(url = %issuer_url))]
async fn refresh_issuer_metadata(state: &Arc<AppState>, issuer_url: &str) -> anyhow::Result<()> {
    info!(%issuer_url, "fetching issuer metadata");
    let url = reqwest::Url::parse(issuer_url).context("parse issuer metadata URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("issuer metadata URL must use HTTPS: {}", issuer_url);
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;
    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .context("issuer metadata request failed")?;
    let wk: WellKnown = res.json().await?;
    let pubkey_bytes =
        Base64UrlUnpadded::decode_vec(&wk.voprf.pubkey).context("base64 decode pubkey")?;
    let public_keys = match load_public_keys(issuer_url, &wk.issuer_id).await {
        Ok(keys) => keys,
        Err(e) => {
            warn!(?e, issuer = %wk.issuer_id, "V5 public bearer key discovery failed");
            HashMap::new()
        }
    };

    let ctx = freebird_crypto::VOPRF_CONTEXT_V4.to_vec();
    let mut keyring = load_verification_keyring()?;
    let verification_key = if let Some(key) = keyring.remove(&wk.voprf.kid) {
        validate_secret_key_matches_pubkey(key, &ctx, &pubkey_bytes)?;
        Some(key)
    } else if let Some(key) = load_default_verification_key()? {
        validate_secret_key_matches_pubkey(key, &ctx, &pubkey_bytes)?;
        Some(key)
    } else {
        warn!(
            issuer = %wk.issuer_id,
            kid = %wk.voprf.kid,
            "issuer metadata refreshed without a private verification key; V4 tokens from this issuer will fail verification"
        );
        None
    };

    let kid_for_log = wk.voprf.kid.clone();
    let ctx_len = ctx.len();
    let mut issuers = state.issuers.write().await;
    let mut deprecated_verification_keys = issuers
        .get(&wk.issuer_id)
        .map(|info| info.deprecated_verification_keys.clone())
        .unwrap_or_default();
    if let Some(previous) = issuers.get(&wk.issuer_id) {
        if previous.kid != wk.voprf.kid {
            if let Some(previous_key) = previous.verification_key {
                deprecated_verification_keys.insert(previous.kid.clone(), previous_key);
            }
        }
    }
    for (kid, key) in keyring {
        if kid != wk.voprf.kid {
            deprecated_verification_keys.insert(kid, key);
        }
    }

    let has_private_key = verification_key.is_some();
    let public_key_count = public_keys.len();
    let info = IssuerInfo {
        pubkey_bytes,
        kid: wk.voprf.kid,
        ctx,
        verification_key,
        deprecated_verification_keys,
        public_keys,
        last_refreshed: Some(Instant::now()),
    };

    issuers.insert(wk.issuer_id.clone(), info);
    info!(issuer = %wk.issuer_id, kid = %kid_for_log, ctx_len, has_private_key, public_key_count, "updated issuer metadata");
    Ok(())
}

// ============================================================================
// Verification handlers
// ============================================================================

async fn verifier_metadata(State(st): State<Arc<AppState>>) -> Json<VerifierMetadataResp> {
    Json(VerifierMetadataResp {
        verifier_id: st.verifier_id.clone(),
        audience: st.audience.clone(),
        scope_digest_b64: Base64UrlUnpadded::encode_string(&st.scope_digest),
    })
}

// Wrapper to catch and log JSON deserialization errors
async fn verify_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("/v1/verify request received");

    match result {
        Ok(Json(req)) => verify(state, Json(req)).await,
        Err(rejection) => {
            error!("JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

// ---------- Verification handler ----------
#[instrument(name = "verify_token", skip_all)]
async fn verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    let version = decode_token_version(&req.token_b64)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (spend_key, ttl) = match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            info!("Starting V4 token verification");
            let issuers = st.issuers.read().await;
            let (parsed, _issuer) = verify_v4_token(&req.token_b64, &issuers, &st.scope_digest)?;
            drop(issuers);
            let null_key =
                freebird_crypto::nullifier_key_v4(&parsed, &st.verifier_id, &st.audience).map_err(
                    |e| {
                        error!(error = ?e, "failed to derive V4 nullifier");
                        (StatusCode::BAD_REQUEST, "verification failed".to_string())
                    },
                )?;
            (format!("freebird:spent:v4:{null_key}"), None)
        }
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => {
            info!("Starting V5 public bearer verification");
            let issuers = st.issuers.read().await;
            let (parsed, key) = verify_v5_public_token(&req.token_b64, &issuers, &st.audience)?;
            drop(issuers);
            let null_key = freebird_crypto::nullifier_key_v5(&parsed).map_err(|e| {
                error!(error = ?e, "failed to derive V5 nullifier");
                (StatusCode::BAD_REQUEST, "verification failed".to_string())
            })?;
            (
                format!("freebird:spent:v5:{null_key}"),
                Some(ttl_until(key.valid_until, now)),
            )
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ))
        }
    };

    debug!("Checking replay for token");
    let spent = st.store.mark_spent(&spend_key, ttl).await.map_err(|e| {
        error!("store error while recording token spend: {e}");
        (StatusCode::INTERNAL_SERVER_ERROR, "store error".into())
    })?;

    if !spent {
        warn!("replay detected (token already used)");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".into()));
    }

    info!("Token verified successfully");

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
        Ok(Json(req)) => check(state, Json(req)).await,
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
/// This endpoint validates the token's V4 format and private authenticator but
/// does NOT mark it as spent. Use this for:
/// - Verifying a user holds a valid Day Pass
/// - Checking token validity before a multi-step operation
/// - Rate-limiting based on token possession without consumption
///
/// The token can still be used with /v1/verify after being checked here.
#[instrument(name = "check_token", skip_all)]
async fn check(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    let version = decode_token_version(&req.token_b64)?;
    let issuers = st.issuers.read().await;
    match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            info!("Starting V4 token check (no consumption)");
            verify_v4_token(&req.token_b64, &issuers, &st.scope_digest)?;
        }
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => {
            info!("Starting V5 public bearer check (no consumption)");
            verify_v5_public_token(&req.token_b64, &issuers, &st.audience)?;
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ))
        }
    }
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // NOTE: We intentionally skip mark_spent() here - this is the key difference from /v1/verify
    // The token remains valid for future use with /v1/verify

    info!("Token check passed (not consumed)");

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

fn ttl_until(valid_until: i64, now: i64) -> Duration {
    Duration::from_secs(valid_until.saturating_sub(now).max(1) as u64)
}

fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

// ---------- Batch Verification Handler (V4) ----------
#[instrument(name = "batch_verify", skip_all, fields(batch_size = req.tokens.len()))]
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

    // Helper function to verify a single token
    let verify_one = |token_req: &TokenToVerify| -> VerifyResult {
        let version = match decode_token_version(&token_req.token_b64) {
            Ok(version) => version,
            Err((_status, msg)) => {
                return VerifyResult::Error {
                    message: msg,
                    code: "verification_failed".to_string(),
                }
            }
        };

        let (spend_key, ttl) = match version {
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
                let parsed = match verify_v4_token(
                    &token_req.token_b64,
                    &issuers_snapshot,
                    &st.scope_digest,
                ) {
                    Ok((parsed, _issuer)) => parsed,
                    Err((_status, msg)) => {
                        return VerifyResult::Error {
                            message: msg,
                            code: "verification_failed".to_string(),
                        };
                    }
                };
                let null_key =
                    match freebird_crypto::nullifier_key_v4(&parsed, &st.verifier_id, &st.audience)
                    {
                        Ok(key) => key,
                        Err(_) => {
                            return VerifyResult::Error {
                                message: "verification failed".to_string(),
                                code: "verification_failed".to_string(),
                            };
                        }
                    };
                (format!("freebird:spent:v4:{null_key}"), None)
            }
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => {
                let (parsed, key) = match verify_v5_public_token(
                    &token_req.token_b64,
                    &issuers_snapshot,
                    &st.audience,
                ) {
                    Ok(result) => result,
                    Err((_status, msg)) => {
                        return VerifyResult::Error {
                            message: msg,
                            code: "verification_failed".to_string(),
                        };
                    }
                };
                let null_key = match freebird_crypto::nullifier_key_v5(&parsed) {
                    Ok(key) => key,
                    Err(_) => {
                        return VerifyResult::Error {
                            message: "verification failed".to_string(),
                            code: "verification_failed".to_string(),
                        };
                    }
                };
                (
                    format!("freebird:spent:v5:{null_key}"),
                    Some(ttl_until(key.valid_until, now)),
                )
            }
            _ => {
                return VerifyResult::Error {
                    message: "unsupported token version".to_string(),
                    code: "verification_failed".to_string(),
                }
            }
        };

        let spent = runtime_handle.block_on(async { st.store.mark_spent(&spend_key, ttl).await });

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

// ---------- Health check handler ----------
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
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
