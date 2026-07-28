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
    BatchVerifyReq, BatchVerifyResp, KeyDiscoveryResp, TokenToVerify, VerifierMetadataResp,
    VerifyReq, VerifyResp, VerifyResult,
};
use freebird_common::logging;
use freebird_common::metrics::{self, MetricsMiddleware};
use freebird_common::spend_key::{v4_spend_key, v5_spend_key};
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
use freebird_verifier::readiness::{self, MetadataStatus, StoreHealth, TokenFamily};
use freebird_verifier::replay_authority::{ReplayAuthorityConfig, ReplayAuthorityHealth};
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
    issuer_urls: Vec<String>,
    metadata: Arc<RwLock<HashMap<String, MetadataStatus>>>,
    accepted_token_families: Vec<TokenFamily>,
    refresh_interval: Duration,
    store_health: StoreHealth,
    replay_authority: Arc<ReplayAuthorityHealth>,
    store_is_memory: bool,
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

fn parse_accepted_token_families(raw: &str) -> anyhow::Result<Vec<TokenFamily>> {
    let mut families = Vec::new();
    for value in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let family = match value.to_ascii_lowercase().as_str() {
            "v4" => TokenFamily::V4,
            "v5" => TokenFamily::V5,
            _ => anyhow::bail!("VERIFIER_ACCEPTED_TOKEN_VERSIONS must contain only v4 and/or v5"),
        };
        if !families.contains(&family) {
            families.push(family);
        }
    }
    if families.is_empty() {
        anyhow::bail!("VERIFIER_ACCEPTED_TOKEN_VERSIONS must enable at least one token family");
    }
    Ok(families)
}

fn in_memory_replay_allowed(
    store_enabled: bool,
    environment: Option<&str>,
    _unsafe_override: bool,
) -> bool {
    // An unsafe override can never turn production into a memory-backed
    // verifier; both the explicit opt-in and development environment are
    // mandatory.
    store_enabled && environment == Some("development")
}

fn parse_in_memory_replay_store(raw: Option<&str>) -> anyhow::Result<bool> {
    match raw {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => anyhow::bail!("IN_MEMORY_REPLAY_STORE must be true or false"),
    }
}

fn select_store_backend(
    redis_url: Option<String>,
    memory_opt_in: bool,
    environment: Option<&str>,
    unsafe_override: bool,
) -> anyhow::Result<(StoreBackend, String)> {
    if let Some(url) = redis_url {
        Ok((StoreBackend::Redis(url), "redis".to_string()))
    } else if in_memory_replay_allowed(memory_opt_in, environment, unsafe_override) {
        Ok((StoreBackend::InMemory, "memory".to_string()))
    } else if memory_opt_in {
        anyhow::bail!(
            "in-memory replay requires IN_MEMORY_REPLAY_STORE=true and VERIFIER_ENV=development"
        )
    } else {
        anyhow::bail!("REDIS_URL is required; development memory replay requires IN_MEMORY_REPLAY_STORE=true and VERIFIER_ENV=development")
    }
}

fn ensure_token_family_enabled(
    version: u8,
    accepted: &[TokenFamily],
) -> Result<(), (StatusCode, String)> {
    let enabled = match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => accepted.contains(&TokenFamily::V4),
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => accepted.contains(&TokenFamily::V5),
        _ => true,
    };
    if enabled {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "token family is not accepted by this verifier".into(),
        ))
    }
}

fn family_enabled(accepted: &[TokenFamily], family: TokenFamily) -> bool {
    accepted.contains(&family)
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
    freebird_verifier::discovery::trusted_public_keys(issuer_id, discovery)
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
    let accepted_raw = std::env::var("VERIFIER_ACCEPTED_TOKEN_VERSIONS")
        .context("VERIFIER_ACCEPTED_TOKEN_VERSIONS is required")?;
    let accepted_token_families = parse_accepted_token_families(&accepted_raw)?;

    let memory_opt_in =
        parse_in_memory_replay_store(std::env::var("IN_MEMORY_REPLAY_STORE").ok().as_deref())?;
    let redis_url = std::env::var("REDIS_URL").ok();
    let (backend, store_backend_name) = select_store_backend(
        redis_url,
        memory_opt_in,
        std::env::var("VERIFIER_ENV").ok().as_deref(),
        std::env::var("VERIFIER_ALLOW_UNSAFE").as_deref() == Ok("true"),
    )?;
    if store_backend_name == "memory" {
        warn!("IN_MEMORY_REPLAY_STORE is enabled; this instance is unsafe for production");
    }
    let store = backend.build().await?;
    let store_health = StoreHealth::new(Arc::clone(&store));

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
    let refresh_interval = Duration::from_secs(refresh_interval_min.saturating_mul(60));

    let verifier_id = std::env::var("VERIFIER_ID")
        .context("VERIFIER_ID is required so V4 tokens are bound to a verifier scope")?;
    let audience = std::env::var("VERIFIER_AUDIENCE").unwrap_or_else(|_| verifier_id.clone());
    let scope_digest = freebird_crypto::build_scope_digest(&verifier_id, &audience)
        .map_err(|e| anyhow!("invalid verifier scope: {:?}", e))?;
    let replay_authority_config = ReplayAuthorityConfig::from_env()?;
    let replay_authority = Arc::new(ReplayAuthorityHealth::new(
        Arc::clone(&store),
        replay_authority_config.clone(),
        scope_digest,
    )?);
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
    let tls_layer = freebird_common::tls_enforcement::TlsEnforcementLayer::from_env()
        .map_err(|e| anyhow!(e))?;

    // Server start time for uptime tracking
    let start_time = Instant::now();

    // Store issuer URLs for admin config
    let issuer_urls_for_admin = issuer_urls.clone();

    let issuers = Arc::new(RwLock::new(HashMap::new()));
    let metadata = Arc::new(RwLock::new(HashMap::new()));
    let state = Arc::new(AppState {
        issuers: Arc::clone(&issuers),
        store: Arc::clone(&store),
        verifier_id: verifier_id.clone(),
        audience: audience.clone(),
        scope_digest,
        epoch_duration_sec,
        epoch_retention,
        issuer_urls: issuer_urls.clone(),
        metadata: Arc::clone(&metadata),
        accepted_token_families: accepted_token_families.clone(),
        refresh_interval,
        store_health: store_health.clone(),
        replay_authority: Arc::clone(&replay_authority),
        store_is_memory: store_backend_name == "memory",
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

    if replay_authority.configured() {
        let replay_authority_task = Arc::clone(&replay_authority);
        tokio::spawn(async move {
            replay_authority_task.run().await;
        });
    }

    // ---------- Router ----------
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler))
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
            accepted_token_versions: accepted_token_families
                .iter()
                .map(|f| {
                    match f {
                        TokenFamily::V4 => "v4",
                        TokenFamily::V5 => "v5",
                    }
                    .to_string()
                })
                .collect(),
            graph_issuer_urls: replay_authority_config.graph_issuer_urls.clone(),
            replay_authority_probe_interval_secs: replay_authority_config.probe_interval.as_secs(),
            replay_authority_max_staleness_secs: replay_authority_config.max_staleness.as_secs(),
        },
        metadata,
        accepted_token_families,
        store_health,
        replay_authority,
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
            .layer(tls_layer),
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
    let require_tls = std::env::var("REQUIRE_TLS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if require_tls && url.scheme() != "https" {
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
    let public_keys = if family_enabled(&state.accepted_token_families, TokenFamily::V5) {
        match load_public_keys(issuer_url, &wk.issuer_id).await {
            Ok(keys) => keys,
            Err(e) => {
                warn!(?e, issuer = %wk.issuer_id, "V5 public bearer key discovery failed");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    // Do not even parse issuer VOPRF key material or read verifier key files
    // when V4 is disabled.  This keeps V5-only deployments independent of V4.
    let (pubkey_bytes, ctx, keyring, verification_key) = if family_enabled(
        &state.accepted_token_families,
        TokenFamily::V4,
    ) {
        let pubkey_bytes =
            Base64UrlUnpadded::decode_vec(&wk.voprf.pubkey).context("base64 decode pubkey")?;
        let ctx = freebird_crypto::VOPRF_CONTEXT_V4.to_vec();
        let mut keyring = load_verification_keyring()?;
        let verification_key = if let Some(key) = keyring.remove(&wk.voprf.kid) {
            validate_secret_key_matches_pubkey(key, &ctx, &pubkey_bytes)?;
            Some(key)
        } else if let Some(key) = load_default_verification_key()? {
            validate_secret_key_matches_pubkey(key, &ctx, &pubkey_bytes)?;
            Some(key)
        } else {
            warn!(issuer = %wk.issuer_id, kid = %wk.voprf.kid, "V4 private verification key unavailable");
            None
        };
        (pubkey_bytes, ctx, keyring, verification_key)
    } else {
        (Vec::new(), Vec::new(), HashMap::new(), None)
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
    drop(issuers);
    state.metadata.write().await.insert(
        issuer_url.to_string(),
        MetadataStatus {
            issuer_id: Some(wk.issuer_id.clone()),
            last_refresh: Some(Instant::now()),
        },
    );
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
        accepted_token_versions: Some(
            st.accepted_token_families
                .iter()
                .map(|family| match family {
                    TokenFamily::V4 => "v4".to_string(),
                    TokenFamily::V5 => "v5".to_string(),
                })
                .collect(),
        ),
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
    ensure_token_family_enabled(version, &st.accepted_token_families)?;
    if version == freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 {
        ensure_v4_replay_authority_ready(&st).await?;
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (spend_key, valid_until) = match version {
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
            (v4_spend_key(&null_key), None)
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
            (v5_spend_key(&null_key), Some(key.valid_until))
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ))
        }
    };

    debug!("Checking replay for token");
    let spent = record_spend(st.store.as_ref(), &spend_key, valid_until)
        .await
        .map_err(|e| {
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
    ensure_token_family_enabled(version, &st.accepted_token_families)?;
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

async fn record_spend(
    store: &dyn SpendStore,
    spend_key: &str,
    valid_until: Option<i64>,
) -> anyhow::Result<bool> {
    match valid_until {
        Some(valid_until) => store.mark_spent_through(spend_key, valid_until).await,
        None => store.mark_spent(spend_key, None).await,
    }
}

fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

async fn ensure_v4_replay_authority_ready(state: &AppState) -> Result<(), (StatusCode, String)> {
    if !state
        .replay_authority
        .allows_v4_replay(state.store_is_memory)
        .await
    {
        error!("V4 replay authority attestation is unavailable");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "replay authority unavailable".to_string(),
        ));
    }
    Ok(())
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

    // Reject disabled families before taking issuer snapshots or doing crypto.
    let mut contains_v4 = false;
    for token in &req.tokens {
        let version = decode_token_version(&token.token_b64)?;
        ensure_token_family_enabled(version, &st.accepted_token_families)?;
        contains_v4 |= version == freebird_crypto::REDEMPTION_TOKEN_VERSION_V4;
    }
    if contains_v4 {
        // Gate the entire batch before taking any spend-store mutation path.
        ensure_v4_replay_authority_ready(&st).await?;
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

        let (spend_key, valid_until) = match version {
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
                (v4_spend_key(&null_key), None)
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
                (v5_spend_key(&null_key), Some(key.valid_until))
            }
            _ => {
                return VerifyResult::Error {
                    message: "unsupported token version".to_string(),
                    code: "verification_failed".to_string(),
                }
            }
        };

        let spent = runtime_handle
            .block_on(async { record_spend(st.store.as_ref(), &spend_key, valid_until).await });

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

/// Process liveness only.  Dependencies intentionally do not affect this endpoint.
async fn readiness_handler(State(st): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    let issuers = st.issuers.read().await.clone();
    let metadata = st.metadata.read().await.clone();
    let report = readiness::evaluate(
        &st.store_health,
        &issuers,
        &metadata,
        &st.issuer_urls,
        &st.accepted_token_families,
        st.refresh_interval,
        Some(&st.replay_authority),
    )
    .await;
    if report.ready() {
        (StatusCode::OK, Json(serde_json::json!({"status": "ready"})))
    } else {
        // Never expose dependency, issuer, or key details on the public endpoint.
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready"})),
        )
    }
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
    use super::{
        compute_throughput, ensure_token_family_enabled, ensure_v4_replay_authority_ready,
        family_enabled, in_memory_replay_allowed, parse_accepted_token_families,
        parse_in_memory_replay_store, record_spend, select_store_backend, AppState,
    };
    use freebird_verifier::readiness::TokenFamily;
    use freebird_verifier::replay_authority::{ReplayAuthorityConfig, ReplayAuthorityHealth};
    use freebird_verifier::store::SpendStore;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::RwLock;

    #[derive(Default)]
    struct RecordingStore {
        calls: Mutex<Vec<(String, Option<i64>)>>,
    }

    #[async_trait::async_trait]
    impl SpendStore for RecordingStore {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn mark_spent(
            &self,
            key: &str,
            ttl: Option<std::time::Duration>,
        ) -> anyhow::Result<bool> {
            assert!(ttl.is_none(), "V4 replay markers must remain non-expiring");
            self.calls.lock().unwrap().push((key.to_string(), None));
            Ok(true)
        }

        async fn mark_spent_through(&self, key: &str, valid_until: i64) -> anyhow::Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push((key.to_string(), Some(valid_until)));
            Ok(true)
        }
    }

    #[test]
    fn test_compute_throughput_zero_time() {
        assert_eq!(compute_throughput(100, 0), 0.0);
    }

    #[test]
    fn test_compute_throughput_normal() {
        assert_eq!(compute_throughput(500, 250), 2000.0);
    }

    #[test]
    fn token_family_configuration_is_explicit_and_rejects_disabled() {
        assert!(parse_accepted_token_families("").is_err());
        let accepted = parse_accepted_token_families("v4").unwrap();
        assert!(ensure_token_family_enabled(
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V4,
            &accepted
        )
        .is_ok());
        assert!(ensure_token_family_enabled(
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V5,
            &accepted
        )
        .is_err());
        assert!(!in_memory_replay_allowed(true, Some("production"), false));
        assert!(!in_memory_replay_allowed(false, Some("development"), false));
        assert!(!in_memory_replay_allowed(true, Some("production"), true));
        assert!(in_memory_replay_allowed(true, Some("development"), false));
    }

    #[test]
    fn refresh_only_uses_enabled_family_configuration() {
        assert!(family_enabled(&[TokenFamily::V4], TokenFamily::V4));
        assert!(!family_enabled(&[TokenFamily::V4], TokenFamily::V5));
        assert!(family_enabled(&[TokenFamily::V5], TokenFamily::V5));
        assert!(!family_enabled(&[TokenFamily::V5], TokenFamily::V4));
    }

    #[test]
    fn parsed_backend_policy_is_fail_closed() {
        assert!(!parse_in_memory_replay_store(None).unwrap());
        assert!(!parse_in_memory_replay_store(Some("false")).unwrap());
        assert!(parse_in_memory_replay_store(Some("invalid")).is_err());

        assert!(select_store_backend(None, false, Some("development"), false).is_err());
        assert!(select_store_backend(None, false, Some("production"), false).is_err());
        assert!(matches!(
            select_store_backend(None, true, Some("development"), false)
                .unwrap()
                .0,
            freebird_verifier::store::StoreBackend::InMemory
        ));
        assert!(select_store_backend(None, true, Some("production"), true).is_err());
    }

    #[test]
    fn redis_backend_selection_has_no_graph_authority_url_policy() {
        assert!(matches!(
            select_store_backend(
                Some("redis://verifier-store:6379/1".into()),
                false,
                Some("production"),
                false,
            )
            .unwrap()
            .0,
            freebird_verifier::store::StoreBackend::Redis(_)
        ));
    }

    #[tokio::test]
    async fn single_and_batch_writes_share_v5_absolute_expiry_and_preserve_v4() {
        let store = RecordingStore::default();

        assert!(record_spend(&store, "single-v5", Some(123)).await.unwrap());
        assert!(record_spend(&store, "batch-v5", Some(123)).await.unwrap());
        assert!(record_spend(&store, "v4", None).await.unwrap());

        assert_eq!(
            *store.calls.lock().unwrap(),
            vec![
                ("single-v5".to_string(), Some(123)),
                ("batch-v5".to_string(), Some(123)),
                ("v4".to_string(), None),
            ]
        );
    }

    #[tokio::test]
    async fn nonparticipating_memory_v4_does_not_gate_spend_mutation() {
        let store = Arc::new(RecordingStore::default());
        let authority = Arc::new(
            ReplayAuthorityHealth::new(
                store.clone(),
                ReplayAuthorityConfig {
                    graph_issuer_urls: vec![],
                    probe_interval: Duration::from_secs(30),
                    max_staleness: Duration::from_secs(60),
                },
                [0; 32],
            )
            .unwrap(),
        );
        let state = AppState {
            issuers: Arc::new(RwLock::new(HashMap::new())),
            store: store.clone(),
            verifier_id: "verifier:test".into(),
            audience: "test".into(),
            scope_digest: [0; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            issuer_urls: vec![],
            metadata: Arc::new(RwLock::new(HashMap::new())),
            accepted_token_families: vec![TokenFamily::V4],
            refresh_interval: Duration::from_secs(60),
            store_health: freebird_verifier::readiness::StoreHealth::new(store.clone()),
            replay_authority: authority,
            store_is_memory: true,
        };
        assert!(ensure_v4_replay_authority_ready(&state).await.is_ok());
        assert!(store.calls.lock().unwrap().is_empty());
    }
}
